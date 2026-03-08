// File: agent/common/types/config.go
package types

import "time"

// AgentConfig represents the runtime configuration for the agent
type AgentConfig struct {
	AgentID           string
	ServerURL         string
	BufferSize        int
	BatchSize         int
	ReportingInterval time.Duration // Time between sending batches
	HeartbeatInterval time.Duration
	TLS               struct {
		VerifyServer bool
	}
}

// DefaultAgentConfig returns a standard configuration
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		ServerURL:         "http://localhost:8080",
		BufferSize:        10000,            // Max events in memory
		BatchSize:         100,              // Events per batch
		ReportingInterval: 30 * time.Second, // Max time delay for batch
		HeartbeatInterval: 60 * time.Second,
		TLS: struct{ VerifyServer bool }{
			VerifyServer: false, // InsecureSkipVerify for testing
		},
	}
}
