// Command tarball packs release files into a .tar.gz with Unix permissions,
// which tar on Windows does not set: the program gets 0755, the rest 0644.
//
//	go run ./tools/tarball -out dist/X.tar.gz -dir VPNCheck -exec vpncheck file...
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func main() {
	out := flag.String("out", "", "archive to write")
	dir := flag.String("dir", "", "top-level folder inside the archive")
	execName := flag.String("exec", "", "base name of the file that gets mode 0755")
	flag.Parse()
	if *out == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: tarball -out file.tar.gz [-dir name] [-exec name] files...")
		os.Exit(2)
	}
	if err := pack(*out, *dir, *execName, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "tarball:", err)
		os.Exit(1)
	}
}

func pack(out, dir, execName string, files []string) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	now := time.Now()
	if dir != "" {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: dir + "/", Mode: 0o755, ModTime: now}); err != nil {
			return err
		}
	}
	for _, p := range files {
		if err := add(tw, p, dir, execName, now); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Close()
}

func add(tw *tar.Writer, p, dir, execName string, now time.Time) error {
	src, err := os.Open(p)
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	name := filepath.Base(p)
	mode := int64(0o644)
	if name == execName {
		mode = 0o755
	}
	if dir != "" {
		name = dir + "/" + name
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: st.Size(), ModTime: now}); err != nil {
		return err
	}
	_, err = io.Copy(tw, src)
	return err
}
