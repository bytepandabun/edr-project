# EDR Project - Phase 1: Basic Agent & API

## 🚀 Quick Start (5 Minutes)

### Prerequisites
- **Go 1.21+** installed
- **Docker & Docker Compose** installed
- **Windows** (for running the agent) or **Linux**
- **Make** (optional, for using Makefile commands)

### Step 1: Clone and Setup
```bash
# Create project structure
mkdir -p edr-project/{agent/{windows,linux,common/{types,buffer,communication}},server/{api/{handlers,models},database},bin}

cd edr-project

# Copy all the code files into their respective directories
# (Use the code from the artifacts provided)
```

### Step 2: Start Infrastructure
```bash
# Start PostgreSQL and Redis
docker-compose up -d

# Wait for database to initialize (10 seconds)
sleep 10

# Verify services are running
docker-compose ps
```

### Step 3: Build Everything
```bash
# Using Make (recommended)
make setup
make all

# OR manually
cd server/api && go build -o ../../bin/edr-project/server
cd ../../agent/windows && GOOS=windows GOARCH=amd64 go build -o ../../bin/edr-agent-windows.exe
```

### Step 4: Run the Server
```bash
# In terminal 1
cd bin
./edr-project/server

# You should see:
# [Main] Starting EDR API server on :8080
```

### Step 5: Run the Agent (Windows)
```bash
# In terminal 2 (on Windows machine)
cd bin
./edr-agent-windows.exe

# You should see:
# [Main] Agent registered successfully!
# [Main] EDR Agent started successfully!
```

### Step 6: Verify It's Working
```bash
# Check registered agents
curl http://localhost:8080/api/v1/agents

# Check events
curl "http://localhost:8080/api/v1/events?agent_id=YOUR-AGENT-ID&limit=10"
```

---

## 📁 Project Structure

```
edr-project/
├── agent/
│   ├── common/
│   │   ├── types/
│   │   │   └── event.go              # Event data structures
│   │   ├── buffer/
│   │   │   └── event_buffer.go       # Thread-safe event buffer
│   │   └── communication/
│   │       └── api_client.go         # HTTP client for server
│   └── windows/
│       ├── main.go                   # Agent entry point
│       ├── collectors/
│       │   └── process_collector.go  # Process monitoring
│       └── go.mod
│
├── server/
│   ├── api/
│   │   ├── main.go                   # API server entry point
│   │   ├── handlers/
│   │   │   └── handlers.go           # HTTP handlers
│   │   ├── models/
│   │   │   └── models.go             # Data models
│   │   └── go.mod
│   └── database/
│       └── schema.sql                # Database schema
│
├── bin/                              # Compiled binaries
├── docker-compose.yml                # Infrastructure
├── Makefile                          # Build automation
└── README.md                         # This file
```

---

## 🔧 Available Make Commands

```bash
# Build
make all                    # Build agent + server
make build-agent-windows    # Build Windows agent only
make build-server           # Build server only

# Run
make setup                  # Setup dev environment
make run-server             # Build and run server
make run-agent-windows      # Build and run agent

# Infrastructure
make infra-up               # Start Docker services
make infra-down             # Stop Docker services
make logs                   # View Docker logs
make db-shell               # Open PostgreSQL shell

# Utilities
make test                   # Run tests
make clean                  # Clean builds
make help                   # Show all commands
```

---

## 🎯 What Phase 1 Does

### Agent Capabilities
✅ **Process Monitoring** - Detects new/terminated processes every 5 seconds
✅ **Event Buffering** - Stores up to 10,000 events in memory
✅ **Batch Sending** - Sends events in batches (100 events or every 30 seconds)
✅ **GZIP Compression** - Compresses data before sending
✅ **Auto-Registration** - Registers with server on first run
✅ **Heartbeat** - Sends health status every 60 seconds

### Server Capabilities
✅ **Agent Registration** - Registers and tracks agents
✅ **Log Ingestion** - Receives and stores events from agents
✅ **GZIP Decompression** - Handles compressed data
✅ **PostgreSQL Storage** - Stores agents and events
✅ **REST API** - Query agents and events
✅ **Health Monitoring** - Tracks agent last_seen status

---

## 📊 Testing the System

### 1. Check Agent Registration
```bash
curl http://localhost:8080/api/v1/agents | jq
```

Expected output:
```json
{
  "agents": [
    {
      "id": "abc-123-...",
      "hostname": "DESKTOP-XYZ",
      "os": "Windows",
      "status": "active",
      "last_seen": "2024-12-13T10:30:00Z"
    }
  ],
  "count": 1
}
```

### 2. View Process Events
```bash
# Get your agent ID first
AGENT_ID=$(curl -s http://localhost:8080/api/v1/agents | jq -r '.agents[0].id')

# Get events
curl "http://localhost:8080/api/v1/events?agent_id=$AGENT_ID&limit=20" | jq
```

Expected output:
```json
{
  "events": [
    {
      "id": "event-123",
      "agent_id": "abc-123",
      "event_type": "process_created",
      "timestamp": "2024-12-13T10:30:15Z",
      "data": {
        "pid": 5432,
        "process_name": "chrome.exe",
        "parent_pid": 1234,
        "user": "DESKTOP\\John"
      }
    }
  ]
}
```

### 3. Monitor Live Activity
```bash
# Watch events in real-time
watch -n 2 'curl -s "http://localhost:8080/api/v1/events?agent_id=$AGENT_ID&limit=5" | jq'
```

### 4. Check Database Directly
```bash
make db-shell

# Inside PostgreSQL shell:
SELECT COUNT(*) FROM agents;
SELECT COUNT(*) FROM events;
SELECT event_type, COUNT(*) FROM events GROUP BY event_type;

# View recent events
SELECT 
  event_type, 
  data->>'process_name' as process, 
  timestamp 
FROM events 
ORDER BY timestamp DESC 
LIMIT 10;
```

---

## 🔍 Monitoring & Debugging

### View Agent Logs
The agent prints logs to stdout:
```
[Main] Agent registered successfully!
[ProcessCollector] New process: notepad.exe (PID: 5678)
[Main] Sending 15 events to server...
[Main] Successfully sent 15 events
```

### View Server Logs
The server prints logs to stdout:
```
[RegisterAgent] New agent registration: DESKTOP-XYZ
[IngestLogs] Received 15 events from agent abc-123
[IngestLogs] Process created: chrome.exe (PID: 5432)
```

### View Docker Logs
```bash
# All services
make logs

# Specific service
docker-compose logs -f postgres
docker-compose logs -f redis
```

### Check Infrastructure Health
```bash
# Check all containers
docker-compose ps

# Check PostgreSQL
docker-compose exec postgres pg_isready -U edr_user

# Check Redis
docker-compose exec redis redis-cli ping
```

---

## 🐛 Troubleshooting

### Agent won't connect to server
**Problem**: `request failed: connection refused`

**Solution**:
```bash
# Make sure server is running
curl http://localhost:8080/health

# If not, start it
make run-server
```

### Database connection error
**Problem**: `Failed to connect to database`

**Solution**:
```bash
# Start PostgreSQL
docker-compose up -d postgres

# Wait and test
sleep 5
docker-compose exec postgres pg_isready -U edr_user
```

### No events showing up
**Problem**: Events not appearing in database

**Solution**:
```bash
# Check agent buffer
# Look for: [Main] Sending X events to server...

# Check server logs
# Look for: [IngestLogs] Received X events from agent

# Query database directly
make db-shell
SELECT COUNT(*) FROM events;
```

### Port already in use
**Problem**: `bind: address already in use`

**Solution**:
```bash
# Find process using port
lsof -i :8080  # macOS/Linux
netstat -ano | findstr :8080  # Windows

# Kill the process or use different port
# Edit server/api/main.go and change :8080
```

---

## 📈 What's Next?

Phase 1 is complete when you can:
- ✅ Agent runs and registers with server
- ✅ Agent detects and sends process events
- ✅ Server receives and stores events
- ✅ You can query agents and events via API

### Phase 2 Preview (Weeks 3-4)
- File monitoring (Minifilter driver)
- Network monitoring (WFP driver)
- Registry monitoring
- Linux eBPF collectors
- More event types

---

## 💡 Development Tips

### Hot Reload During Development
```bash
# Terminal 1: Run server with auto-restart
while true; do make run-server; sleep 2; done

# Terminal 2: Rebuild on file change
find server -name "*.go" | entr make build-server
```

### Testing Without Agent
```bash
# Send fake event directly
curl -X POST http://localhost:8080/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -H "X-Agent-ID: test-agent-123" \
  -d '{
    "agent_id": "test-agent-123",
    "batch_id": "batch-1",
    "timestamp": "2024-12-13T10:00:00Z",
    "events": [
      {
        "id": "event-1",
        "agent_id": "test-agent-123",
        "type": "process_created",
        "timestamp": "2024-12-13T10:00:00Z",
        "hostname": "test-host",
        "data": {
          "pid": 1234,
          "process_name": "test.exe"
        }
      }
    ]
  }'
```

---

## 🎓 Understanding the Code Flow

### Agent Startup Flow
```
1. main.go starts
2. Generates/loads agent ID
3. Creates event buffer (10,000 capacity)
4. Creates API client
5. Registers with server (POST /api/v1/agents/register)
6. Starts process collector
7. Enters main loop:
   - Every 5s: Scan for new/terminated processes
   - Every 30s: Send event batch to server
   - Every 60s: Send heartbeat
```

### Event Journey
```
1. Process created on endpoint
2. ProcessCollector detects it (via Windows API)
3. Creates Event struct
4. Adds to EventBuffer
5. Main loop retrieves batch (100 events)
6. Compresses with gzip
7. Sends to server (POST /api/v1/logs/ingest)
8. Server decompresses
9. Server validates
10. Server stores in PostgreSQL
11. Available via API
```

---

## 🤝 Contributing

Phase 1 is the foundation. Once working:
1. Test thoroughly
2. Document any issues
3. Move to Phase 2

---

## 📞 Support

**Common Issues**: See Troubleshooting section above
**Database Issues**: `make db-shell` to inspect directly
**Network Issues**: Check firewall allows port 8080

---

**Phase 1 Complete! 🎉**

You now have a working EDR agent that monitors processes and reports to a central server. This is the foundation for all future features!