// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// writeStdout writes every byte to stdout. A full PIPE_NOWAIT pipe takes 0 bytes and reports success: os.File.Write
// retried at once, a busy loop (one CPU second per second, CI run 46013986663). On a pipe the wait is a 10 ms sleep
// (the equivalent of poll, which takes no pipe on Windows); 0 bytes on anything else is an error.
func writeStdout(b []byte) error {
	h := syscall.Handle(os.Stdout.Fd())
	t, _ := syscall.GetFileType(h)
	pipe := t == syscall.FILE_TYPE_PIPE
	for len(b) > 0 {
		var n uint32
		if err := syscall.WriteFile(h, b, &n, nil); err != nil {
			return err
		}
		if n == 0 {
			if !pipe {
				return errors.New("short write: 0 bytes taken")
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		b = b[n:]
	}
	return nil
}
