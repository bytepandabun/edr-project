package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"edr-project/agent/common/buffer"
	"edr-project/agent/common/types"

	"github.com/fsnotify/fsnotify"
)

type FileMonitor struct {
	buffer   *buffer.EventBuffer
	agentID  string
	hostname string
	watcher  *fsnotify.Watcher
	stopCh   chan struct{}
}

func NewFileMonitor(buf *buffer.EventBuffer, agentID, hostname string) *FileMonitor {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Failed to create file watcher: %v", err)
		return nil
	}
	return &FileMonitor{buffer: buf, agentID: agentID, hostname: hostname, watcher: watcher, stopCh: make(chan struct{})}
}

func (f *FileMonitor) Start() error {
	// 1. Get User Home Directory (e.g., C:\Users\vaibh)
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("[FileMonitor] Error getting home dir: %v\n", err)
		homeDir = "C:\\Users\\"
	}

	fmt.Printf("[FileMonitor] Starting watcher for user: %s\n", homeDir)

	// 2. Watch Critical User Folders Explicitly (Fsnotify is NOT recursive)
	pathsToWatch := []string{
		homeDir,
		filepath.Join(homeDir, "Desktop"),
		filepath.Join(homeDir, "Downloads"),
		filepath.Join(homeDir, "Documents"),
		filepath.Join(homeDir, "Music"),                    // <--- ADDED
		filepath.Join(homeDir, "Pictures"),                 // <--- ADDED
		filepath.Join(homeDir, "Videos"),                   // <--- ADDED
		filepath.Join(homeDir, "AppData", "Local", "Temp"), // Common malware drop spot
		filepath.Join("C:\\"),                              // Another common temp folder
	}

	for _, p := range pathsToWatch {
		// Check if path exists before adding
		if _, err := os.Stat(p); err == nil {
			if err := f.watcher.Add(p); err != nil {
				fmt.Printf("[FileMonitor] Warning: Could not watch %s: %v\n", p, err)
			} else {
				fmt.Printf("[FileMonitor] Watching: %s\n", p)
			}
		}
	}

	go f.watchLoop()
	return nil
}

func (f *FileMonitor) Stop() error {
	f.watcher.Close()
	close(f.stopCh)
	return nil
}

func (f *FileMonitor) watchLoop() {
	for {
		select {
		case <-f.stopCh:
			return
		case event, ok := <-f.watcher.Events:
			if !ok {
				return
			}
			// Catch Create, Write, and Rename (Critical for Copy/Move detection)
			if event.Op&fsnotify.Create == fsnotify.Create ||
				event.Op&fsnotify.Write == fsnotify.Write ||
				event.Op&fsnotify.Rename == fsnotify.Rename {

				// Run in goroutine to not block watcher during hashing retry
				go f.handleFileEvent(event.Name)
			}
		case err, ok := <-f.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[FileMonitor] Error: %v", err)
		}
	}
}

func (f *FileMonitor) handleFileEvent(filePath string) {
	// Filter noise (Logs, Temp, Agent files)
	if strings.Contains(filePath, ".log") || strings.Contains(filePath, ".tmp") {
		return
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	suspiciousExts := map[string]bool{".exe": true, ".ps1": true, ".bat": true, ".vbs": true, ".scr": true, ".jar": true}

	if suspiciousExts[ext] {
		// RETRY LOOP: Windows locks copied files briefly. We must wait/retry.
		var fileHash string
		var err error

		for i := 0; i < 5; i++ {
			// Wait 200ms, 400ms, 600ms...
			time.Sleep(time.Duration((i+1)*200) * time.Millisecond)

			fileHash, err = f.calculateFileHash(filePath)
			if err == nil && fileHash != "access_denied" {
				break // Success!
			}
		}

		if fileHash == "" || fileHash == "access_denied" {
			// Could not read file after retries (system lock or deletion)
			return
		}

		fmt.Printf("[FILE] Suspicious file found: %s (Hash: %s)\n", filePath, fileHash)

		// SEND ALERT to Server
		event := types.NewEvent("SUSPICIOUS_FILE", f.agentID, f.hostname, map[string]interface{}{
			"path":        filePath,
			"extension":   ext,
			"file_hash":   fileHash,
			"description": "New executable created on disk",
			"timestamp":   time.Now().UTC(),
		})
		f.buffer.Push(event)
	}
}

func (f *FileMonitor) calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "access_denied", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "read_error", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
