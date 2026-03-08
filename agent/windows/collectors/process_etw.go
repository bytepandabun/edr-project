package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"edr-project/agent/common/buffer"
	"edr-project/agent/common/types"

	"golang.org/x/sys/windows"
)

type ProcessETWCollector struct {
	buffer        *buffer.EventBuffer
	agentID       string
	hostname      string
	stopCh        chan struct{}
	sessionHandle windows.Handle
}

func NewProcessETWCollector(buf *buffer.EventBuffer, agentID, hostname string) *ProcessETWCollector {
	return &ProcessETWCollector{
		buffer:   buf,
		agentID:  agentID,
		hostname: hostname,
		stopCh:   make(chan struct{}),
	}
}

func (c *ProcessETWCollector) Start() error {
	fmt.Println("[Collector] Starting Real-Time Process Monitor...")
	go c.runRealTimeSession()
	return nil
}

func (c *ProcessETWCollector) runRealTimeSession() {
	// Polling faster (1s) to catch processes
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	seen := make(map[uint32]bool)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.scanEvents(seen)
		}
	}
}

func (c *ProcessETWCollector) scanEvents(seen map[uint32]bool) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return
	}

	for {
		if !seen[entry.ProcessID] && entry.ProcessID != 0 {
			seen[entry.ProcessID] = true
			c.emitProcessEvent(entry)
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
}

func (c *ProcessETWCollector) emitProcessEvent(entry windows.ProcessEntry32) {
	name := windows.UTF16ToString(entry.ExeFile[:])

	// 1. Get Full Path (Needed for hashing)
	fullPath := c.getProcessPath(entry.ProcessID)

	// 2. Calculate SHA256 Hash (The "Fingerprint")
	fileHash := "unknown"
	if fullPath != "" {
		fileHash = c.calculateFileHash(fullPath)
	}

	// 3. Get Command Line
	cmdLine := c.getCommandLine(entry.ProcessID)

	// --- DETECTION LOGIC START ---
	cmdLower := strings.ToLower(cmdLine)
	procName := strings.ToLower(name)

	var event types.Event

	// TIER 1: DEFINITIVE THREATS (AUTO-KILL)
	if strings.Contains(cmdLower, "-encodedcommand") ||
		strings.Contains(cmdLower, "-windowstyle hidden") ||
		strings.Contains(cmdLower, "bypass -noprofile") {

		fmt.Printf("[BLOCK] Malicious behavior detected: %s\n", cmdLine)

		// 1. AUTO-ACTION: Kill Process Immediately
		proc, err := os.FindProcess(int(entry.ProcessID))
		if err == nil {
			errKill := proc.Kill()
			if errKill == nil {
				fmt.Printf("[BLOCK] SUCCESS: Threat PID %d terminated automatically.\n", entry.ProcessID)
			} else {
				fmt.Printf("[BLOCK] FAILED to kill PID %d: %v\n", entry.ProcessID, errKill)
			}
		}

		// 2. REPORT: Send "Critical" Alert
		eventData := map[string]interface{}{
			"title":        "Malicious Process Blocked",
			"severity":     "critical",
			"description":  fmt.Sprintf("Auto-Killed malicious PowerShell. Cmd: %s", cmdLine),
			"command_line": cmdLine, // <--- ADDED: Explicit Command Line Field
			"path":         fullPath,
			"pid":          entry.ProcessID,
			"status":       "resolved", // Mark as resolved since we killed it
			"file_hash":    fileHash,
			"timestamp":    time.Now().UTC(),
		}
		event = types.NewEvent("THREAT_BLOCKED", c.agentID, c.hostname, eventData)

	} else if strings.Contains(procName, "powershell.exe") || strings.Contains(procName, "cmd.exe") {
		// TIER 2: SUSPICIOUS ACTIVITY (MANUAL REVIEW)
		fmt.Printf("[ALERT] Suspicious process started: %s\n", cmdLine)

		// 1. NO ACTION: Do NOT kill. Let it run.

		// 2. REPORT: Send "High" Alert
		eventData := map[string]interface{}{
			"title":        "Suspicious Process Detected",
			"severity":     "high",
			"description":  fmt.Sprintf("Review required. Process: %s. Cmd: %s", procName, cmdLine),
			"command_line": cmdLine, // <--- ADDED: Explicit Command Line Field
			"path":         fullPath,
			"pid":          entry.ProcessID,
			"status":       "open", // Mark as open so user knows to investigate
			"file_hash":    fileHash,
			"timestamp":    time.Now().UTC(),
		}
		event = types.NewEvent("SUSPICIOUS_ACTIVITY", c.agentID, c.hostname, eventData)

	} else {
		// STANDARD EVENT (Just Logging)
		eventData := map[string]interface{}{
			"pid":          entry.ProcessID,
			"parent_pid":   entry.ParentProcessID,
			"process_name": name,
			"image_path":   fullPath,
			"file_hash":    fileHash,
			"command_line": cmdLine,
			"timestamp":    time.Now().UTC(),
		}
		event = types.NewEvent("process_created", c.agentID, c.hostname, eventData)
	}

	c.buffer.Push(event)
}

// Helper to get full path from PID using WMIC
func (c *ProcessETWCollector) getProcessPath(pid uint32) string {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("processid=%d", pid), "get", "ExecutablePath")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "ExecutablePath" {
			return line
		}
	}
	return ""
}

// Helper to calculate SHA256
func (c *ProcessETWCollector) calculateFileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "access_denied"
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "error"
	}

	return hex.EncodeToString(h.Sum(nil))
}

func (c *ProcessETWCollector) getCommandLine(pid uint32) string {
	cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("processid=%d", pid), "get", "commandline")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "CommandLine" {
			return line
		}
	}
	return ""
}

func (c *ProcessETWCollector) Stop() error {
	close(c.stopCh)
	return nil
}
