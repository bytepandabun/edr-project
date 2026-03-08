package collectors

import (
	"fmt"
	"time"

	"edr-project/agent/common/buffer"
	"edr-project/agent/common/types"

	"golang.org/x/sys/windows/registry"
)

type RegistryCollector struct {
	buffer   *buffer.EventBuffer
	agentID  string
	hostname string
	stopCh   chan struct{}
	// Cache to store known values: KeyPath -> (ValueName -> ValueData)
	knownValues map[string]map[string]string
}

func NewRegistryCollector(buf *buffer.EventBuffer, agentID, hostname string) *RegistryCollector {
	return &RegistryCollector{
		buffer:      buf,
		agentID:     agentID,
		hostname:    hostname,
		stopCh:      make(chan struct{}),
		knownValues: make(map[string]map[string]string),
	}
}

func (c *RegistryCollector) Start() error {
	fmt.Println("[Collector] Starting Registry Persistence Monitor...")

	// Initial Snapshot
	c.scanPersistenceKeys(true) // true = initial scan (don't alert)

	go c.runLoop()
	return nil
}

func (c *RegistryCollector) Stop() error {
	close(c.stopCh)
	return nil
}

func (c *RegistryCollector) runLoop() {
	// Poll every 5 seconds (Persistence doesn't need ms-level precision)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.scanPersistenceKeys(false) // false = alert on new items
		}
	}
}

// Critical Persistence Keys to Monitor
var persistenceKeys = []struct {
	Hive registry.Key
	Path string
	Name string
}{
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, "HKCU_Run"},
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "HKCU_RunOnce"},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM_Run"},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM_RunOnce"},
	// Added Services (Common persistence method)
	{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, "HKLM_Services"},
}

func (c *RegistryCollector) scanPersistenceKeys(isInitial bool) {
	for _, pk := range persistenceKeys {
		k, err := registry.OpenKey(pk.Hive, pk.Path, registry.READ)
		if err != nil {
			continue // Key might not exist, skip
		}

		// Read all value names
		names, err := k.ReadValueNames(0)
		k.Close() // Close immediately after reading names
		if err != nil {
			continue
		}

		// Initialize map for this key if missing
		if _, ok := c.knownValues[pk.Path]; !ok {
			c.knownValues[pk.Path] = make(map[string]string)
		}

		currentSnapshot := make(map[string]string)

		// Re-open to read values (cleaner than keeping open)
		k, err = registry.OpenKey(pk.Hive, pk.Path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		for _, name := range names {
			val, _, err := k.GetStringValue(name)
			if err != nil {
				continue
			}
			currentSnapshot[name] = val

			// CHECK: Is this new?
			if !isInitial {
				if _, exists := c.knownValues[pk.Path][name]; !exists {
					c.reportPersistence(pk.Name, pk.Path, name, val)
				} else if c.knownValues[pk.Path][name] != val {
					// Value changed (e.g., malware modified an existing run key)
					c.reportPersistence(pk.Name, pk.Path, name, val+" (Modified)")
				}
			}
		}
		k.Close()

		// Update Cache
		c.knownValues[pk.Path] = currentSnapshot
	}
}

func (c *RegistryCollector) reportPersistence(hiveName, keyPath, valueName, valueData string) {
	fmt.Printf("[PERSISTENCE] Suspicious Registry Key: %s\\%s -> %s\n", keyPath, valueName, valueData)

	event := types.NewEvent("PERSISTENCE_DETECTED", c.agentID, c.hostname, map[string]interface{}{
		"severity":     "high",
		"title":        "Persistence Mechanism Detected",
		"description":  fmt.Sprintf("New Startup Item found: %s", valueName),
		"registry_key": keyPath,
		"value_name":   valueName,
		"value_data":   valueData,
		"method":       hiveName, // e.g., HKCU_Run
		"timestamp":    time.Now().UTC(),
	})
	c.buffer.Push(event)
}
