package main

import (
	"fmt"
	"os/exec"
)

func printPlatformInfo() {
	fmt.Println("\n=== Linux User Info (id) ===")
	out, err := exec.Command("id").Output()
	if err != nil {
		fmt.Println("Error running id:", err)
		return
	}
	fmt.Print(string(out))
}
