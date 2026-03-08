package types

import "time"

// --- Event Types ---

const (
	EventTypeProcessCreated    = "process_created"
	EventTypeProcessTerminated = "process_terminated"
	EventTypeFileCreated       = "file_created"
	EventTypeFileModified      = "file_modified"
	EventTypeFileDeleted       = "file_deleted"
	EventTypeNetworkConnect    = "network_connection"
)

type Event struct {
	ID        string                 `json:"id"`
	AgentID   string                 `json:"agent_id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Hostname  string                 `json:"hostname"`
	Data      map[string]interface{} `json:"data"`
}

type EventBatch struct {
	AgentID   string    `json:"agent_id"`
	BatchID   string    `json:"batch_id"`
	Timestamp time.Time `json:"timestamp"`
	Events    []Event   `json:"events"`
}

// NewEvent creates a generic event with a UTC timestamp
func NewEvent(eventType, agentID, hostname string, data map[string]interface{}) Event {
	return Event{
		AgentID:   agentID,
		Type:      eventType,
		Timestamp: time.Now().UTC(),
		Hostname:  hostname,
		Data:      data,
	}
}

// --- Registration & Heartbeat ---

type AgentRegistration struct {
	AgentID     string `json:"agent_id"`
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	OSVersion   string `json:"os_version"`
	IPAddress   string `json:"ip_address"`
	MACAddress  string `json:"mac_address"`
	InstalledAt string `json:"installed_at"`
	Version     string `json:"version"`
}

type AgentRegistrationResponse struct {
	Status      string      `json:"status"`
	AgentID     string      `json:"agent_id"`
	Config      AgentConfig `json:"config"`
	Token       string      `json:"token"`
	Certificate string      `json:"certificate,omitempty"`
}

type AgentHeartbeat struct {
	AgentID       string  `json:"agent_id"`
	Timestamp     string  `json:"timestamp"`
	Status        string  `json:"status"`
	CPUUsage      float64 `json:"cpu_usage"`
	MemoryUsageMB float64 `json:"memory_usage"`
	EventsQueued  int     `json:"events_queued"`
	LastEventTime string  `json:"last_event_time"`
}

// --- Command Structures ---

type Command struct {
	CommandID  string                 `json:"command_id"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Priority   string                 `json:"priority"`
}

type CommandsResponse struct {
	Commands []Command `json:"commands"`
}

type CommandResult struct {
	Status    string    `json:"status"`
	Output    string    `json:"output"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// --- Specific Event Data Structures ---

type ProcessEvent struct {
	PID         uint32 `json:"pid"`
	ParentPID   uint32 `json:"parent_pid"`
	ProcessName string `json:"process_name"`
	ProcessPath string `json:"process_path"`
	CommandLine string `json:"command_line"`
	User        string `json:"user"`
	HashSHA256  string `json:"hash_sha256,omitempty"`
}

type FileEvent struct {
	FilePath  string `json:"file_path"`
	Operation string `json:"operation"` // create, delete, modify
	ProcessID uint32 `json:"process_id,omitempty"`
}

type NetworkEvent struct {
	ProcessID  uint32 `json:"process_id"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Protocol   string `json:"protocol"`  // TCP, UDP
	Direction  string `json:"direction"` // inbound, outbound
}
