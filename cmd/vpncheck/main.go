// Command vpncheck starts the local backend and opens the UI in the default browser.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"vpncheck/internal/api"
	"vpncheck/internal/app"
	"vpncheck/internal/demo"
	"vpncheck/internal/i18n"
	"vpncheck/internal/limiter"
	"vpncheck/internal/model"
	"vpncheck/internal/probe"
	"vpncheck/internal/registry"
	"vpncheck/internal/runner"
	"vpncheck/internal/server"
	"vpncheck/internal/speed"
	"vpncheck/internal/store"
	"vpncheck/web"
)

type instanceInfo struct {
	PID   int    `json:"pid"`
	Port  int    `json:"port"`
	Token string `json:"token"`
}

func main() {
	var (
		port      = flag.Int("port", 0, i18n.T("порт на 127.0.0.1 (0 — свободный)"))
		noBrowser = flag.Bool("no-browser", false, i18n.T("не открывать браузер"))
		dataDir   = flag.String("data-dir", "", i18n.T("каталог данных (по умолчанию %LOCALAPPDATA%\\VPNCheck)"))
		version   = flag.Bool("version", false, i18n.T("показать версию и выйти"))
		demo      = flag.Bool("demo", false, i18n.T("ДЕМО-режим для проверки интерфейса: подставные результаты, без сетевых запросов, отдельный каталог данных"))
	)
	flag.Parse()
	if *version {
		fmt.Println(app.Name, app.Version)
		return
	}
	if *demo && *dataDir == "" {
		*dataDir = filepath.Join(os.TempDir(), "VPNCheck-demo")
	}
	if err := run(*port, *noBrowser, *dataDir, *demo); err != nil {
		fmt.Fprintln(os.Stderr, "vpncheck:", err)
		os.Exit(1)
	}
}

func run(port int, noBrowser bool, dataDirOverride string, demoMode bool) error {
	dir, err := app.DataDir(dataDirOverride)
	if err != nil {
		return err
	}
	logger, closeLog := openLog(dir)
	defer closeLog()
	logger.Printf("%s %s, каталог данных %s", app.Name, app.Version, dir)
	if demoMode {
		logger.Printf("ДЕМО-РЕЖИМ: результаты подставные, сетевые запросы не выполняются")
	}

	instPath := filepath.Join(dir, "instance.json")
	if info, ok := readInstance(instPath); ok && instanceAlive(info) {
		logger.Printf("уже запущен экземпляр на порту %d, открываю его", info.Port)
		if !noBrowser {
			return openBrowser(fmt.Sprintf("http://127.0.0.1:%d/session?t=%s", info.Port, info.Token))
		}
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	quitCtx, quit := context.WithCancel(ctx)
	defer quit()

	st, err := store.Open(dir)
	if err != nil {
		return i18n.Errorf("каталог данных недоступен: %w", err)
	}
	settings, settingsInfo, _ := st.LoadSettings()
	if settingsInfo.Corrupt {
		logger.Printf("settings.json повреждён, копия: %s", settingsInfo.Backup)
	}
	reg, regInfo := registry.Load(st)
	if regInfo.Corrupt || regInfo.Invalid != "" {
		logger.Printf("registry.json не применён: corrupt=%v invalid=%q", regInfo.Corrupt, regInfo.Invalid)
	}
	lim := limiter.New(st, time.Now)
	if demoMode {
		lim.RunCooldown = 5 * time.Second // QA only; production uses the user's setting
		lim.SpeedCooldown = 10 * time.Second
	} else if settings.RunCooldownSec > 0 {
		lim.RunCooldown = time.Duration(settings.RunCooldownSec) * time.Second
	}

	var runr *runner.Runner
	var speedr *speed.Runner
	srv, err := server.New(server.Config{
		UI:   web.FS(),
		Port: port,
		OnQuit: func() {
			if runr != nil {
				runr.Cancel()
			}
			if speedr != nil {
				speedr.Cancel()
			}
			quit()
		},
		Logger: logger,
	})
	if err != nil {
		return err
	}
	runnerDeps := runner.Deps{
		Store:    st,
		Registry: reg,
		Limiter:  lim,
		Publish:  srv.Hub().Publish,
		Logger:   logger,
	}
	if demoMode {
		runnerDeps.NewProber = demo.New
	}
	runr = runner.New(runnerDeps)
	speedDeps := speed.Deps{Store: st, Limiter: lim, Publish: srv.Hub().Publish, Logger: logger, Demo: demoMode,
		NewMeter: func(route model.RouteConfig) speed.Meter {
			return speed.NewHTTPMeter(probe.New(probe.Options{Route: route}), speed.Config{})
		}}
	if demoMode {
		speedDeps.NewMeter = demo.NewSpeedMeter
	}
	speedr = speed.NewRunner(speedDeps)
	api.Mount(api.Deps{
		Demo:         demoMode,
		Server:       srv,
		Store:        st,
		Registry:     reg,
		RegistryInfo: regInfo,
		Limiter:      lim,
		Runner:       runr,
		Speed:        speedr,
		Settings:     settings,
		SettingsInfo: settingsInfo,
		Logger:       logger,
	})
	if err := srv.Listen(); err != nil {
		return i18n.Errorf("не удалось открыть порт на 127.0.0.1: %w", err)
	}
	logger.Printf("слушаю %s", srv.BaseURL())

	if err := writeInstance(instPath, instanceInfo{PID: os.Getpid(), Port: srv.Port(), Token: srv.LaunchToken()}); err != nil {
		logger.Printf("не удалось записать instance.json: %v", err)
	}
	// Remove the instance file only if it is still ours: a newer instance may
	// have replaced it while this one was shutting down.
	defer func() {
		if info, ok := readInstance(instPath); ok && info.PID == os.Getpid() {
			_ = os.Remove(instPath)
		}
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	if !noBrowser {
		if err := openBrowser(srv.LaunchURL()); err != nil {
			logger.Printf("не удалось открыть браузер: %v. Откройте вручную: %s", err, srv.LaunchURL())
		}
	} else {
		fmt.Println(i18n.T("Откройте в браузере:"), srv.LaunchURL())
	}

	select {
	case <-quitCtx.Done():
	case err := <-serveErr:
		if err != nil {
			return err
		}
	}
	logger.Printf("завершение")
	if runr.Cancel() {
		runr.Wait()
	}
	shCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(shCtx)
}

// openLog appends to vpncheck.log (several processes may briefly share it) and
// rotates it once to vpncheck.log.1 when it grows past 512 KiB.
func openLog(dir string) (*log.Logger, func()) {
	path := filepath.Join(dir, "vpncheck.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 512*1024 {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return log.New(os.Stderr, "", log.LstdFlags), func() {}
	}
	return log.New(io.MultiWriter(f, os.Stderr), "", log.LstdFlags), func() { _ = f.Close() }
}

func readInstance(path string) (instanceInfo, bool) {
	var info instanceInfo
	b, err := os.ReadFile(path)
	if err != nil {
		return info, false
	}
	if json.Unmarshal(b, &info) != nil || info.Port <= 0 || info.Token == "" {
		return info, false
	}
	return info, true
}

func writeInstance(path string, info instanceInfo) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// instanceAlive checks that the recorded port is served by VPN Check and not by
// an unrelated process that happened to reuse the port.
func instanceAlive(info instanceInfo) bool {
	c := &http.Client{
		Timeout: 1500 * time.Millisecond,
		Transport: &http.Transport{
			Proxy:       nil, // never route loopback checks through any proxy
			DialContext: (&net.Dialer{Timeout: time.Second}).DialContext,
		},
	}
	resp, err := c.Get("http://127.0.0.1:" + strconv.Itoa(info.Port) + "/api/instance")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode == http.StatusOK && resp.Header.Get("X-VPNCheck-Instance") == app.Name
}

// openBrowser hands the URL to the default browser without a shell.
func openBrowser(url string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	if err := cmd.Start(); err != nil {
		return errors.New("rundll32: " + err.Error())
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
