package communication

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	// Import the shared types package to ensure consistency across the agent
	"edr-project/agent/common/types"
)

// APIClient handles communication with the EDR server
type APIClient struct {
	baseURL    string
	agentID    string
	token      string
	httpClient *http.Client
	mu         sync.RWMutex

	// Statistics
	stats APIStats
}

// APIStats tracks API client statistics
type APIStats struct {
	TotalRequests      uint64
	SuccessfulRequests uint64
	FailedRequests     uint64
	TotalRetries       uint64
	TotalBytesSent     uint64
	LastRequestTime    time.Time
	LastSuccessTime    time.Time
	LastErrorTime      time.Time
	LastError          string
}

// NewAPIClient creates a new API client with optimized transport settings
func NewAPIClient(baseURL string, tlsConfig *tls.Config) *APIClient {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	return &APIClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:       tlsConfig,
				MaxIdleConns:          10,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				DisableCompression:    false,
				DisableKeepAlives:     false,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		stats: APIStats{},
	}
}

// NewAPIClientWithCerts creates a client using custom mutual TLS certificates
func NewAPIClientWithCerts(baseURL, clientCert, clientKey, serverCA string) (*APIClient, error) {
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	caCert, err := os.ReadFile(serverCA)
	if err != nil {
		return nil, fmt.Errorf("failed to read server CA: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse server CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	return NewAPIClient(baseURL, tlsConfig), nil
}

// Register registers the agent with the server using types.AgentRegistration
func (c *APIClient) Register(registration types.AgentRegistration) (*types.AgentRegistrationResponse, error) {
	url := fmt.Sprintf("%s/api/v1/agents/register", c.baseURL)

	body, err := json.Marshal(registration)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Version", registration.Version)
	req.Header.Set("User-Agent", fmt.Sprintf("EDR-Agent/%s", registration.Version))

	c.updateStats(true, len(body), nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.updateStats(false, 0, err)
		return nil, fmt.Errorf("failed to send registration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		c.updateStats(false, 0, err)
		return nil, err
	}

	var regResp types.AgentRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		c.updateStats(false, 0, err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	c.mu.Lock()
	c.agentID = regResp.AgentID
	c.token = regResp.Token
	c.mu.Unlock()

	c.updateStats(false, 0, nil)
	return &regResp, nil
}

// SendEvents sends a batch of events to the server using types.Event
func (c *APIClient) SendEvents(events []types.Event) error {
	if len(events) == 0 {
		return nil
	}

	c.mu.RLock()
	agentID := c.agentID
	c.mu.RUnlock()

	// Use shared types.EventBatch to ensure server compatibility
	batch := types.EventBatch{
		BatchID:   generateBatchID(),
		AgentID:   agentID,
		Timestamp: time.Now().UTC(),
		Events:    events,
	}

	// Compress the batch before sending to save bandwidth
	compressedData, err := CompressJSON(batch)
	if err != nil {
		return fmt.Errorf("failed to compress batch: %w", err)
	}

	return c.sendWithRetry(compressedData, batch.BatchID)
}

// sendWithRetry sends data with exponential backoff retry logic
func (c *APIClient) sendWithRetry(data []byte, batchID string) error {
	url := fmt.Sprintf("%s/api/v1/logs/ingest", c.baseURL)
	maxRetries := 5
	baseDelay := 1 * time.Second

	c.mu.RLock()
	agentID := c.agentID
	token := c.token
	c.mu.RUnlock()

	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Agent-Token", token)
		req.Header.Set("X-Batch-ID", batchID)
		req.Header.Set("User-Agent", "EDR-Agent/1.0.0")

		c.updateStats(true, len(data), nil)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			c.updateStats(false, 0, err)

			if attempt < maxRetries {
				c.mu.Lock()
				c.stats.TotalRetries++
				c.mu.Unlock()

				delay := baseDelay * time.Duration(1<<uint(attempt))
				time.Sleep(delay)
				continue
			}
			return fmt.Errorf("failed to send events after %d attempts: %w", maxRetries+1, err)
		}

		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
			c.updateStats(false, 0, nil)
			return nil
		}

		if resp.StatusCode >= 500 && attempt < maxRetries {
			bodyBytes, _ := io.ReadAll(resp.Body)
			lastErr = fmt.Errorf("server error %d: %s", resp.StatusCode, string(bodyBytes))
			c.updateStats(false, 0, lastErr)

			c.mu.Lock()
			c.stats.TotalRetries++
			c.mu.Unlock()

			delay := baseDelay * time.Duration(1<<uint(attempt))
			time.Sleep(delay)
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		err = fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(bodyBytes))
		c.updateStats(false, 0, err)
		return err
	}

	return fmt.Errorf("failed to send events after %d attempts: %w", maxRetries+1, lastErr)
}

// SendHeartbeat sends agent health status using types.AgentHeartbeat
func (c *APIClient) SendHeartbeat(heartbeat types.AgentHeartbeat) error {
	url := fmt.Sprintf("%s/api/v1/agents/heartbeat", c.baseURL)

	c.mu.RLock()
	agentID := c.agentID
	token := c.token
	c.mu.RUnlock()

	body, err := json.Marshal(heartbeat)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("X-Agent-Token", token)

	c.updateStats(true, len(body), nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.updateStats(false, 0, err)
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		err := fmt.Errorf("heartbeat failed with status %d: %s", resp.StatusCode, string(bodyBytes))
		c.updateStats(false, 0, err)
		return err
	}

	c.updateStats(false, 0, nil)
	return nil
}

// GetCommands retrieves pending commands from the server
func (c *APIClient) GetCommands() ([]types.Command, error) {
	c.mu.RLock()
	agentID := c.agentID
	token := c.token
	c.mu.RUnlock()

	url := fmt.Sprintf("%s/api/v1/agents/%s/commands", c.baseURL, agentID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("X-Agent-Token", token)

	c.updateStats(true, 0, nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.updateStats(false, 0, err)
		return nil, fmt.Errorf("failed to get commands: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("get commands failed with status %d", resp.StatusCode)
		c.updateStats(false, 0, err)
		return nil, err
	}

	var response types.CommandsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		c.updateStats(false, 0, err)
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	c.updateStats(false, 0, nil)
	return response.Commands, nil
}

// SendCommandResult sends the result of a command using types.CommandResult
func (c *APIClient) SendCommandResult(commandID string, result types.CommandResult) error {
	c.mu.RLock()
	agentID := c.agentID
	token := c.token
	c.mu.RUnlock()

	url := fmt.Sprintf("%s/api/v1/agents/%s/commands/%s/result", c.baseURL, agentID, commandID)

	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("X-Agent-Token", token)

	c.updateStats(true, len(body), nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.updateStats(false, 0, err)
		return fmt.Errorf("failed to send result: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("send result failed with status %d", resp.StatusCode)
		c.updateStats(false, 0, err)
		return err
	}

	c.updateStats(false, 0, nil)
	return nil
}

// TestConnection tests the connection to the server health endpoint
func (c *APIClient) TestConnection() error {
	url := fmt.Sprintf("%s/health", c.baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection test failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	return nil
}

// GetStats returns current API client statistics
func (c *APIClient) GetStats() APIStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// ResetStats clears all statistics
func (c *APIClient) ResetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats = APIStats{}
}

func (c *APIClient) updateStats(isRequest bool, bytesSent int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if isRequest {
		c.stats.TotalRequests++
		c.stats.TotalBytesSent += uint64(bytesSent)
		c.stats.LastRequestTime = now
	} else {
		if err != nil {
			c.stats.FailedRequests++
			c.stats.LastErrorTime = now
			c.stats.LastError = err.Error()
		} else {
			c.stats.SuccessfulRequests++
			c.stats.LastSuccessTime = now
		}
	}
}

func (c *APIClient) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = token
}

func (c *APIClient) SetAgentID(agentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agentID = agentID
}

func (c *APIClient) GetAgentID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.agentID
}

func (c *APIClient) Close() {
	c.httpClient.CloseIdleConnections()
}

func generateBatchID() string {
	return fmt.Sprintf("batch-%d", time.Now().UnixNano())
}
