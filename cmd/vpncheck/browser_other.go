//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
)

// openBrowser hands the URL to the desktop's default browser without a shell:
// xdg-open on Linux, open on macOS. Without a graphical session (a server over
// SSH) it fails and the caller prints the URL instead.
func openBrowser(url string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	} else if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errors.New("no graphical session (DISPLAY/WAYLAND_DISPLAY)")
	}
	cmd := exec.Command(name, url)
	if err := cmd.Start(); err != nil {
		return errors.New(name + ": " + err.Error())
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
