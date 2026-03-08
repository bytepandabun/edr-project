package collectors

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type YaraScanner struct {
	binaryPath string
	rulePath   string
}

func NewYaraScanner() *YaraScanner {
	// 1. Get the directory where agent.exe is running
	exePath, err := os.Executable()
	if err != nil {
		// Fallback for dev mode
		return &YaraScanner{
			binaryPath: "yara64.exe",
			rulePath:   "rules\\malware.yar",
		}
	}
	exeDir := filepath.Dir(exePath)

	// 2. Build paths relative to the executable (Portable Mode)
	// This looks for yara64.exe in the same folder as agent.exe
	return &YaraScanner{
		binaryPath: filepath.Join(exeDir, "yara64.exe"),
		rulePath:   filepath.Join(exeDir, "rules", "malware.yar"),
	}
}

func (y *YaraScanner) ScanFile(filePath string) (string, error) {
	// Safety Check: Does the binary exist?
	if _, err := os.Stat(y.binaryPath); os.IsNotExist(err) {
		return "", fmt.Errorf("yara binary not found at %s", y.binaryPath)
	}

	// Execute YARA command: yara64.exe -w -r rules/malware.yar target_file
	cmd := exec.Command(y.binaryPath, "-w", y.rulePath, filePath)

	// Capture output
	var out bytes.Buffer
	cmd.Stdout = &out

	// We ignore errors because YARA returns exit code 1 on warnings
	_ = cmd.Run()

	output := out.String()
	if output == "" {
		return "", nil // No match
	}

	// Parse Output: YARA prints "RuleName FilePath"
	// Example: "RustDesk_Remote_Tool C:\Users\Vaibh\Desktop\rustdesk.exe"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			ruleName := parts[0]
			return ruleName, nil // Found a match!
		}
	}

	return "", nil
}
