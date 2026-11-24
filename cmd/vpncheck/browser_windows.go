package main

import (
	"errors"
	"os/exec"
)

// openBrowser hands the URL to the default browser without a shell.
func openBrowser(url string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	if err := cmd.Start(); err != nil {
		return errors.New("rundll32: " + err.Error())
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
