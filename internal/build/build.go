package build

// Default build-time values. These are overridden via -ldflags at link time.
var (
	GitSHA    = "unknown"
	BuildTime = "unknown"
)
