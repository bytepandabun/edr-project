package communication

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
)

// CompressJSON compresses data to JSON and then gzip
func CompressJSON(data interface{}) ([]byte, error) {
	// Marshal to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Compress with gzip
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)

	if _, err := gzipWriter.Write(jsonData); err != nil {
		return nil, fmt.Errorf("failed to write gzip data: %w", err)
	}

	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}

// DecompressJSON decompresses gzip data and unmarshals JSON
func DecompressJSON(compressedData []byte, result interface{}) error {
	// Create gzip reader
	buf := bytes.NewBuffer(compressedData)
	gzipReader, err := gzip.NewReader(buf)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	// Read decompressed data
	decompressedData, err := io.ReadAll(gzipReader)
	if err != nil {
		return fmt.Errorf("failed to read decompressed data: %w", err)
	}

	// Unmarshal JSON
	if err := json.Unmarshal(decompressedData, result); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return nil
}

// CompressBytes compresses raw bytes with gzip
func CompressBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)

	if _, err := gzipWriter.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write gzip data: %w", err)
	}

	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}

// DecompressBytes decompresses gzip data
func DecompressBytes(compressedData []byte) ([]byte, error) {
	buf := bytes.NewBuffer(compressedData)
	gzipReader, err := gzip.NewReader(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	decompressedData, err := io.ReadAll(gzipReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	return decompressedData, nil
}
