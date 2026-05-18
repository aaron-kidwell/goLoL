package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// RTL_OSVERSIONINFOEXW mirrors the Win32 struct used by RtlGetVersion.
type RTL_OSVERSIONINFOEXW struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion      uint32
	dwMinorVersion      uint32
	dwBuildNumber       uint32
	dwPlatformId        uint32
	szCSDVersion        [128]uint16
	wServicePackMajor   uint16
	wServicePackMinor   uint16
	wSuiteMask          uint16
	wProductType        uint8
	wReserved           uint8
}

func getOSVersion() (major, minor, build uint32, err error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion := ntdll.NewProc("RtlGetVersion")

	var info RTL_OSVERSIONINFOEXW
	info.dwOSVersionInfoSize = uint32(unsafe.Sizeof(info))
	ret, _, _ := rtlGetVersion.Call(uintptr(unsafe.Pointer(&info)))
	if ret != 0 {
		return 0, 0, 0, fmt.Errorf("RtlGetVersion failed: 0x%x", ret)
	}
	return info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber, nil
}

func getMemoryStatus() (totalMB, availMB uint64, err error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")

	type MEMORYSTATUSEX struct {
		dwLength                uint32
		dwMemoryLoad            uint32
		ullTotalPhys            uint64
		ullAvailPhys            uint64
		ullTotalPageFile        uint64
		ullAvailPageFile        uint64
		ullTotalVirtual         uint64
		ullAvailVirtual         uint64
		ullAvailExtendedVirtual uint64
	}

	var ms MEMORYSTATUSEX
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 {
		return 0, 0, fmt.Errorf("GlobalMemoryStatusEx failed")
	}
	return ms.ullTotalPhys / 1024 / 1024, ms.ullAvailPhys / 1024 / 1024, nil
}

func printPlatformInfo() {
	fmt.Println("\n=== OS Version (RtlGetVersion syscall) ===")
	if major, minor, build, err := getOSVersion(); err == nil {
		fmt.Printf("Version: %d.%d (Build %d)\n", major, minor, build)
	} else {
		fmt.Println("Error:", err)
	}

	fmt.Println("\n=== Memory (GlobalMemoryStatusEx syscall) ===")
	if total, avail, err := getMemoryStatus(); err == nil {
		fmt.Printf("Total: %d MB\n", total)
		fmt.Printf("Available: %d MB\n", avail)
	} else {
		fmt.Println("Error:", err)
	}
}