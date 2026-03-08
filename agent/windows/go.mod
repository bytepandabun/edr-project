module edr-project/agent/windows

go 1.25.5

require (
	edr-project/agent/common v0.0.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/google/uuid v1.6.0
	golang.org/x/sys v0.39.0
)

replace edr-project/agent/common => ../common
