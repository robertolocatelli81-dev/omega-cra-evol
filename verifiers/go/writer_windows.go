// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"os"
	"syscall"
	"time"
)

// writeStdout writes every byte to stdout. A full PIPE_NOWAIT pipe takes 0 bytes and reports success: os.File.Write
// retried at once, a busy loop (one CPU second per second, CI run 46013986663). On a pipe the wait is a 10 ms sleep
// (the equivalent of poll, which takes no pipe on Windows); a console or a file is written by os.File.Write, as before.
func writeStdout(b []byte) error {
	h := syscall.Handle(os.Stdout.Fd())
	t, _ := syscall.GetFileType(h)
	if t != syscall.FILE_TYPE_PIPE { // a console or a file: os.File.Write as before 0.13.2 (on a console it writes UTF-16
		// with WriteConsoleW; WriteFile would hand the UTF-8 bytes to the console's code page)
		_, err := os.Stdout.Write(b)
		return err
	}
	for len(b) > 0 {
		var n uint32
		if err := syscall.WriteFile(h, b, &n, nil); err != nil {
			return err
		}
		if n == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		b = b[n:]
	}
	return nil
}
