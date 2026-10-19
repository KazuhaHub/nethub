//go:build windows

package setup

func ownerUID(string) int { return -1 }
