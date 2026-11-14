//go:build !linux

package main

import "os"

func bootstrap() { os.Exit(1) }
