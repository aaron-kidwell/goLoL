package main

import (
	"fmt"
	"runtime"

	windows "golang.org/x/sys/windows"
)

func main() {
	fmt.Println("\n=== System Information ===")
	fmt.Println("Operating System:", runtime.GOOS)
	fmt.Println("Architecture:", runtime.GOARCH)
	fmt.Println("CPU Cores:", runtime.NumCPU())
	hostname, err := windows.ComputerName()
	if err != nil {
		fmt.Println("Hostname:", err)
	} else {
		fmt.Println("Hostname:", hostname)
	}

}
