//go:build !windows

package sysenv

import (
	"errors"

	"vpncheck/internal/i18n"
)

func osVersion() string                  { return i18n.T("не Windows") }
func adapters() ([]Adapter, error)       { return nil, errors.New(i18n.T("только Windows")) }
func defaultRoute([]Adapter) Route       { return Route{Note: i18n.T("только Windows")} }
func tcpListeners() ([]Listener, error)  { return nil, errors.New(i18n.T("только Windows")) }
func processes() (map[int]string, error) { return nil, errors.New(i18n.T("только Windows")) }
