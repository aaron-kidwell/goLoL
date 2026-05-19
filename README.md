# offensive-go

Windows host reconnaissance tool written in Go. Collects basic system information, lists running processes (with parent PID), and flags running executables that lack an embedded Authenticode signature.

Uses in-process `WinVerifyTrust` via `wintrust.dll` — no PowerShell, no child processes, no external verifier binary.

## Features

- **System information** — OS, architecture, CPU count, memory, hostname
- **Process enumeration** — PID, PPID, process name, full command line
- **Unsigned binary detection** — scans unique executable paths and reports processes whose on-disk image has no embedded signature (`TRUST_E_NOSIGNATURE`)

## Requirements

- **Go** 1.21+ (project uses Go 1.26.2)
- **Windows** for signature verification (other sections may run elsewhere with limited value)

## Install

```bash
git clone https://github.com/aaron-kidwell/offensive-go.git
cd offensive-go
go mod download
```

## Usage

```bash
go run .
```

Or build a binary:

```bash
go build -o offensive-go.exe .
.\offensive-go.exe
```

### Example output

```
=== System Information ===
Operating System: windows
Architecture: amd64
CPU Cores: 16
...

=== Running Processes ===
PID 1234 PPID 5678: example.exe - "C:\path\to\example.exe" ...

=== Unsigned Binaries (in-process WinVerifyTrust) ===
PID 25272: main.exe
  C:\Users\...\AppData\Local\Temp\go-build...\main.exe
```

## How it works

| Component | Package / API |
|-----------|----------------|
| Process & memory stats | [gopsutil](https://github.com/shirou/gopsutil) |
| Signature check | `internal/signverify` → `WinVerifyTrust` (`wintrust.dll`) |

Unsigned detection checks **embedded** Authenticode signatures only. Catalog-signed system binaries under `\Windows\` are skipped to reduce false positives. Many legitimate tools (Go binaries, dev tools) appear unsigned — triage results in context.

## Project layout

```
.
├── main.go
├── internal/
│   └── signverify/
│       ├── signverify_windows.go   # WinVerifyTrust implementation
│       └── signverify_stub.go      # non-Windows stub
├── go.mod
└── go.sum
```

## Tests

```bash
go test ./...
```

## Disclaimer

For **authorized** security testing, lab use, and education only. Only run against systems you own or have explicit permission to assess. The authors are not responsible for misuse.

## License

MIT
