package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"edr-project/agent/common/buffer"
	"edr-project/agent/common/communication"
	"edr-project/agent/common/types"
	"edr-project/agent/windows/collectors"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	AgentVersion = "1.0.0"
	ServiceName  = "EDRAgent"
)

func main() {
	flag.Parse()
	isService, _ := svc.IsWindowsService()
	if isService {
		runService()
	} else {
		if err := runConsole(); err != nil {
			log.Fatal(err)
		}
	}
}

func runConsole() error {
	fmt.Println("EDR Agent v" + AgentVersion)
	fmt.Println("Running in console mode...")

	agent, err := NewAgent()
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}

	if err := agent.Start(); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
	agent.Stop()
	return nil
}

func runService() { fmt.Println("Running as Windows service...") }

type Agent struct {
	config     *types.AgentConfig
	agentID    string
	hostname   string
	buffer     *buffer.EventBuffer
	batchMgr   *buffer.BatchManager
	apiClient  *communication.APIClient
	collectors []Collector
}

type Collector interface {
	Start() error
	Stop() error
}

func NewAgent() (*Agent, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	agentID := loadOrGenerateAgentID()
	config := types.DefaultAgentConfig()
	config.AgentID = agentID

	// Increase buffer slightly to handle bursts
	eventBuffer := buffer.NewEventBuffer(2000)

	tlsConfig := &tls.Config{InsecureSkipVerify: !config.TLS.VerifyServer}
	apiClient := communication.NewAPIClient(config.ServerURL, tlsConfig)

	agent := &Agent{
		config:     config,
		agentID:    agentID,
		hostname:   hostname,
		buffer:     eventBuffer,
		apiClient:  apiClient,
		collectors: []Collector{},
	}

	return agent, nil
}

func (a *Agent) Start() error {
	fmt.Printf("Starting EDR Agent (ID: %s, Hostname: %s)\n", a.agentID, a.hostname)

	if err := a.register(); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	a.batchMgr = buffer.NewBatchManager(a.buffer, a.config.BatchSize, a.config.ReportingInterval, a.onBatchReady)
	a.batchMgr.Start()

	if err := a.startCollectors(); err != nil {
		return fmt.Errorf("failed to start collectors: %w", err)
	}

	go a.heartbeatLoop()
	return nil
}

func (a *Agent) Stop() {
	fmt.Println("Stopping agent...")
	for _, c := range a.collectors {
		c.Stop()
	}
	if a.batchMgr != nil {
		a.batchMgr.Stop()
	}
}

func (a *Agent) register() error {
	fmt.Println("Registering with server...")
	reg := types.AgentRegistration{
		AgentID:     a.agentID,
		Hostname:    a.hostname,
		OS:          "Windows",
		OSVersion:   getWindowsVersion(),
		IPAddress:   getLocalIP(),
		MACAddress:  getMACAddress(),
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Version:     AgentVersion,
	}
	resp, err := a.apiClient.Register(reg)
	if err == nil {
		fmt.Printf("Registration successful. Status: %s\n", resp.Status)
	}
	return err
}

func (a *Agent) startCollectors() error {
	fmt.Println("Starting collectors...")

	// 1. Process Collector (Includes Auto-Kill Logic for PowerShell)
	proc := collectors.NewProcessETWCollector(a.buffer, a.agentID, a.hostname)
	if err := proc.Start(); err != nil {
		return err
	}
	a.collectors = append(a.collectors, proc)

	// 2. File Monitor (Lightweight - No YARA)
	files := collectors.NewFileMonitor(a.buffer, a.agentID, a.hostname)
	if err := files.Start(); err != nil {
		fmt.Printf("Warning: File monitor failed: %v\n", err)
	} else {
		a.collectors = append(a.collectors, files)
	}

	// 3. Registry Collector
	reg := collectors.NewRegistryCollector(a.buffer, a.agentID, a.hostname)
	if err := reg.Start(); err != nil {
		fmt.Printf("Warning: Registry collector failed: %v\n", err)
	} else {
		a.collectors = append(a.collectors, reg)
	}

	fmt.Println("All collectors started successfully")
	return nil
}

func (a *Agent) onBatchReady(events []types.Event) {
	if len(events) > 0 {
		fmt.Printf("Sending batch of %d events...\n", len(events))
		a.apiClient.SendEvents(events)
	}
}

func (a *Agent) heartbeatLoop() {
	ticker := time.NewTicker(3 * time.Second) // Poll every 3s for fast command response
	defer ticker.Stop()

	for range ticker.C {
		a.sendHeartbeat()
		a.checkAndExecuteCommands()
	}
}

func (a *Agent) sendHeartbeat() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	hb := types.AgentHeartbeat{
		AgentID:       a.agentID,
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Status:        "healthy",
		CPUUsage:      getCPUUsage(),
		MemoryUsageMB: float64(memStats.Alloc) / 1024 / 1024,
		EventsQueued:  a.buffer.Size(),
		LastEventTime: time.Now().UTC().Format(time.RFC3339),
	}
	a.apiClient.SendHeartbeat(hb)
}

func (a *Agent) checkAndExecuteCommands() {
	cmds, err := a.apiClient.GetCommands()
	if err != nil {
		return
	}

	for _, cmd := range cmds {
		fmt.Printf("[COMMAND] Received: %s (ID: %s)\n", cmd.Type, cmd.CommandID)

		status := "failed"
		output := "Unknown command"

		switch cmd.Type {
		case "kill_process":
			status, output = a.handleKillProcess(cmd)
		case "delete_file":
			status, output = a.handleDeleteFile(cmd)
		case "list_files":
			status, output = a.handleListFiles(cmd)
		case "hash_file":
			status, output = a.handleHashFile(cmd)
		}

		a.apiClient.SendCommandResult(cmd.CommandID, types.CommandResult{
			Status:    status,
			Output:    output,
			Timestamp: time.Now().UTC(),
		})
	}
}

func (a *Agent) handleKillProcess(cmd types.Command) (string, string) {
	// Robust PID Parsing: Handles float64 (from JSON numbers) and int
	var pid int
	if pFloat, ok := cmd.Parameters["pid"].(float64); ok {
		pid = int(pFloat)
	} else if pInt, ok := cmd.Parameters["pid"].(int); ok {
		pid = pInt
	} else {
		return "failed", "Invalid PID format"
	}

	fmt.Printf("[KILL] Attempting to terminate PID %d...\n", pid)

	proc, err := os.FindProcess(pid)
	if err != nil {
		return "failed", fmt.Sprintf("Process %d not found", pid)
	}

	// Attempt Kill
	if err := proc.Kill(); err != nil {
		// If it's already dead (e.g., Auto-Killed by Process Collector), report success
		if strings.Contains(err.Error(), "process already finished") || err == os.ErrProcessDone {
			return "success", "Process was already terminated"
		}
		return "failed", fmt.Sprintf("Kill failed: %v", err)
	}

	fmt.Printf("[KILL] SUCCESS: PID %d terminated.\n", pid)
	return "success", fmt.Sprintf("Process %d terminated", pid)
}

func (a *Agent) handleDeleteFile(cmd types.Command) (string, string) {
	path, ok := cmd.Parameters["path"].(string)
	if !ok || path == "" {
		return "failed", "Invalid path"
	}
	path = strings.TrimSpace(path)
	fmt.Printf("[DELETE] Targeting: %s\n", path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "failed", fmt.Sprintf("File not found: %s", path)
	}

	os.Chmod(path, 0777)
	if err := os.RemoveAll(path); err != nil {
		// Retry once after small delay
		time.Sleep(200 * time.Millisecond)
		if err = os.RemoveAll(path); err != nil {
			return "failed", fmt.Sprintf("Access Denied: %v", err)
		}
	}
	return "success", fmt.Sprintf("Deleted: %s", path)
}

func (a *Agent) handleListFiles(cmd types.Command) (string, string) {
	path, ok := cmd.Parameters["path"].(string)
	if !ok || path == "" {
		path = "C:\\"
	}
	fmt.Printf("[EXPLORER] Listing files in: %s\n", path)

	entries, err := os.ReadDir(path)
	if err != nil {
		return "failed", err.Error()
	}

	var lines []string
	for _, e := range entries {
		prefix := "[FILE] "
		if e.IsDir() {
			prefix = "[DIR]  "
		}
		lines = append(lines, fmt.Sprintf("%s%s", prefix, e.Name()))
	}
	return "success", strings.Join(lines, "\n")
}

func (a *Agent) handleHashFile(cmd types.Command) (string, string) {
	path, ok := cmd.Parameters["path"].(string)
	if !ok || path == "" {
		return "failed", "Invalid path"
	}
	fmt.Printf("[HASH] Hashing file: %s\n", path)

	f, err := os.Open(path)
	if err != nil {
		return "failed", "File read error"
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "failed", "Hash error"
	}
	hash := hex.EncodeToString(h.Sum(nil))
	fmt.Printf("[HASH] SHA256: %s\n", hash)
	return "success", hash
}

// Helpers
func loadOrGenerateAgentID() string {
	path := "C:\\ProgramData\\EDR\\agent_id.txt"
	if d, err := os.ReadFile(path); err == nil {
		return string(d)
	}
	id := uuid.New().String()
	os.MkdirAll("C:\\ProgramData\\EDR", 0755)
	os.WriteFile(path, []byte(id), 0644)
	return id
}
func getWindowsVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
func getLocalIP() string    { return "127.0.0.1" }
func getMACAddress() string { return "00:00:00:00:00:00" }
func getCPUUsage() float64  { return 0.0 }
