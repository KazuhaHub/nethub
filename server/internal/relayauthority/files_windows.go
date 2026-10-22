package relayauthority

import "os"

// Windows exercises content semantics locally; the privileged host is Linux.
func owned(os.FileInfo) bool     { return true }
func syncDirectory(string) error { return nil }
