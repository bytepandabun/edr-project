# File: Makefile

# Variables
BIN_DIR = bin
SERVER_PATH = server/api
AGENT_PATH = agent/windows
SERVER_OUT = $(BIN_DIR)/edr-project/server
AGENT_WIN_OUT = $(BIN_DIR)/edr-agent-windows.exe

# Phony targets are commands that don't produce a file named after the target
.PHONY: all setup build-server build-agent-windows run-server infra-up infra-down logs clean

# Default target
all: build-server build-agent-windows
	@echo "--- All components built! ---"

# --- Update the 'setup' target in your Makefile ---
setup:
	@echo "Setting up Go module dependencies..."
	cd server/api && go mod download
	cd agent/windows && go mod download
	@echo "--- Setup complete ---"

# Build Commands
build-server:
	@echo "Building server for Linux/WSL..."
	@mkdir -p $(BIN_DIR)
	cd $(SERVER_PATH) && go build -o ../../$(SERVER_OUT)
	@echo "Server binary created: $(SERVER_OUT)"

build-agent-windows:
	@echo "Building Windows agent (Cross-compiling)..."
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o $(AGENT_WIN_OUT) $(AGENT_PATH)/main.go
	@echo "Agent binary created: $(AGENT_WIN_OUT)"

# Run Commands (Requires build first)
run-server: build-server
	@echo "Running server on :8080..."
	./$(SERVER_OUT)

# Infrastructure Commands (Using docker-compose.yml)
infra-up:
	@echo "Starting PostgreSQL and Redis..."
	docker-compose up -d

infra-down:
	@echo "Stopping PostgreSQL and Redis..."
	docker-compose down

logs:
	docker-compose logs -f

# Utility
clean:
	@echo "Cleaning up binaries and temporary files..."
	rm -rf $(BIN_DIR)/*