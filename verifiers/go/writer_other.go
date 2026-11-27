// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !windows

package main

import "os"

// writeStdout writes every byte to stdout (a full non-blocking stdout is waited for by the runtime's poller).
func writeStdout(b []byte) error {
	_, err := os.Stdout.Write(b)
	return err
}
