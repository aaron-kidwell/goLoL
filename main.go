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
	fmt.Println("Hostname:", windows.GetComputerName())

}
