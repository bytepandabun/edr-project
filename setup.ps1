# setup.ps1 - Create EDR Project Structure

# Create directory structure
$dirs = @(
    "agent\common\types",
    "agent\common\buffer",
    "agent\common\communication",
    "agent\windows\collectors",
    "server\api\handlers",
    "server\api\models",
    "server\database",
    "bin"
)

foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# Create empty files
$files = @(
    "agent\common\types\event.go",
    "agent\common\buffer\event_buffer.go",
    "agent\common\communication\api_client.go",
    "agent\windows\main.go",
    "agent\windows\go.mod",
    "agent\windows\collectors\process_collector.go",
    "server\api\main.go",
    "server\api\go.mod",
    "server\api\handlers\handlers.go",
    "server\api\models\models.go",
    "server\database\schema.sql",
    "docker-compose.yml",
    "Makefile",
    "README.md",
    ".gitignore"
)

foreach ($file in $files) {
    if (-not (Test-Path $file)) {
        New-Item -ItemType File -Path $file -Force | Out-Null
    }
}

Write-Host " Project structure created!" -ForegroundColor Green
Write-Host "Now copy the code into each file" -ForegroundColor Yellow