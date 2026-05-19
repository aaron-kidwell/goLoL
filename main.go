package main

import (
	"dev/internal/signverify"
	"fmt"
	"os"
	"runtime"

	memory "github.com/shirou/gopsutil/v3/mem"
	process "github.com/shirou/gopsutil/v3/process"
)

func main() {
	printSystemInfo()
	printRunningProcesses()
	printUnsignedProcesses()
}

func printRunningProcesses() {
	fmt.Println("=== Running Processes ===")

	processes, err := process.Processes()
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}
		cmdline, err := p.Cmdline()
		if err != nil {
			continue
		}

		ppid, err := p.Ppid()
		if err != nil {
			continue
		}

		fmt.Printf("PID %d PPID %d: %s - %s\n\n", p.Pid, ppid, name, cmdline)
	}
}

func printUnsignedProcesses() {
	fmt.Println("=== Unsigned Binaries (in-process WinVerifyTrust) ===")

	if runtime.GOOS != "windows" {
		fmt.Println("signature check requires Windows")
		return
	}
	if err := signverify.MustLoad(); err != nil {
		fmt.Println("signverify:", err)
		return
	}

	processes, err := process.Processes()
	if err != nil {
		fmt.Println(err)
		return
	}

	seen := make(map[string]struct{})
	found := 0

	for _, p := range processes {
		exe, err := p.Exe()
		if err != nil || exe == "" {
			continue
		}
		if _, ok := seen[exe]; ok {
			continue
		}
		seen[exe] = struct{}{}

		unsigned, err := signverify.IsUnsigned(exe)
		if err != nil || !unsigned {
			continue
		}

		name, _ := p.Name()
		fmt.Printf("PID %d: %s\n  %s\n\n", p.Pid, name, exe)
		found++
	}

	if found == 0 {
		fmt.Println("none found (or no accessible exe paths)")
	}
}

func printSystemInfo() {
	fmt.Println("\n=== System Information ===")
	fmt.Println("Operating System:", runtime.GOOS)
	fmt.Println("Architecture:", runtime.GOARCH)
	fmt.Println("CPU Cores:", runtime.NumCPU())
	mem, _ := memory.VirtualMemory()
	fmt.Printf("Total Memory: %.2f GB\n", float64(mem.Total)/(1024*1024*1024))
	fmt.Printf("Free Memory: %.2f GB\n", float64(mem.Free)/(1024*1024*1024))
	hostname, _ := os.Hostname()
	fmt.Println("Hostname:", hostname)
	fmt.Println()
}
