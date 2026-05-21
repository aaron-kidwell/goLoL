# goLoL

**goLoL** is a Windows host scanner that finds [LOLBAS](https://lolbas-project.github.io/) binaries present on the current machine and lists techniques you can run **at your current privilege level** with MITRE ATT&CK mappings and example commands.
**Note:** This is not an OPSEC safe tool.
**Author:** Aaron Kidwell

```
                   █████                █████      
                  ░░███                ░░███       
  ███████  ██████  ░███         ██████  ░███       
 ███░░███ ███░░███ ░███        ███░░███ ░███       
░███ ░███░███ ░███ ░███       ░███ ░███ ░███       
░███ ░███░███ ░███ ░███      █░███ ░███ ░███      █
░░███████░░██████  ███████████░░██████  ███████████
 ░░░░░███ ░░░░░░  ░░░░░░░░░░░  ░░░░░░  ░░░░░░░░░░░ 
 ███ ░███                                          
░░██████                                           
 ░░░░░░                                            

```

## Features

- **Live LOLBAS catalog** — pulls the latest entries from [lolbas-project.github.io](https://lolbas-project.github.io/api/lolbas.json)
- **On-disk detection** — resolves documented paths to local `%WINDIR%`, `%ProgramFiles%`, `%USERPROFILE%`, and WindowsApps locations
- **Privilege-aware filtering** — shows only techniques runnable at your current tier
- **MITRE ATT&CK labels** — technique IDs mapped to readable names (e.g. `T1003.003: NTDS`)
- **Flexible sorting** — group by binary, privilege tier, or ATT&CK technique
- **Plain output mode** — ASCII-only output for telnet, reverse shells, and other unstable terminals
- **Lightweight scanning** — filesystem checks via Go APIs; admin-group detection uses `net localgroup` (one child process on Windows)

## Privilege tiers

| Your context | What you see |
|---|---|
| Standard user | User-tier techniques |
| Member of local **Administrators** | User-tier + admin-tier techniques |
| **NT AUTHORITY\\SYSTEM** | User-tier + admin-tier + SYSTEM-tier techniques |

Admin-tier commands may still require an elevated shell even if your account is in the Administrators group. SYSTEM-tier entries are hidden unless the process token is SYSTEM (`S-1-5-18`).

## Requirements

- **Windows** (primary target; non-Windows builds stub out privilege checks)
- **Go 1.21+** (project uses Go 1.26.2)
- **Network access** to fetch the LOLBAS JSON catalog on each run (not cached offline)

## Install

```bash
git clone https://github.com/aaron-kidwell/goLoL.git
cd goLoL
go mod download
```

## Usage

Run from the module root (required for `internal/` packages):

```bash
go run .
```

Build a binary (recommended.. strips debug info, ~30% smaller):

```bash
go build -ldflags="-s -w" -trimpath -o golol.exe .
.\golol.exe
```

`-s -w` removes the symbol table and DWARF debug data. A default `go build` on this project is ~9.5 MB; with those flags it drops to ~6.4 MB.

### Flags

| Flag | Description |
|---|---|
| `-h`, `-help` | Show help |
| `-plain` | ASCII-only output — no colors, Unicode, or cursor control |
| `-sort` | Sort results: `binary` (default), `privilege`, or `attack` |

Sort aliases: `b`, `priv` / `p`, `mitre` / `a`. Invalid values print an error and show help.

### Examples

```bash
# Default — grouped by binary name (A–Z)
go run .

# Admin tier first, then user tier (SYSTEM tier first when running as SYSTEM)
go run . -sort privilege

# Sorted by MITRE ATT&CK ID
go run . -sort attack

# Reverse shell / telnet friendly output
go run . -plain

# Combine flags
go run . -plain -sort attack
```

### Example output

Counts and binaries vary by host. Examples below are illustrative.

**Interactive mode** (colored terminal, grouped by binary):

```
  Role:        administrator
  Sort:        binary
  Binaries:    147
  Techniques:  299

  ╭─ [1] Esentutl.exe
  Path          C:\Windows\System32\esentutl.exe
  Description   Binary for working with Microsoft JET database
  ├─ technique 1
  Privileges    Admin
  ATT&CK        T1003.003: NTDS
  Use case      Copy/extract a locked file such as the AD Database
  Command       esentutl.exe /y /vss c:\windows\ntds\ntds.dit /d {PATH_ABSOLUTE:.dit}
  ╰───────────────────────────────────────────────────────────────
```

**Plain mode** (`-plain`):

```
[*] Checking process token...
[*] Fetching LOLBAS catalog...
[+] Found 147 binaries, 299 techniques

==============================================================
Role:        administrator
Sort:        binary
Binaries:    147
Techniques:  299
==============================================================

  [1] Esentutl.exe
  Path:          C:\Windows\System32\esentutl.exe
  ...
```

## How it works

1. Detects the current process privilege context (standard user, local admin group member, or SYSTEM).
2. Downloads and parses the LOLBAS JSON catalog.
3. For each entry, remaps documented paths to the local filesystem and checks whether the binary exists.
4. Filters commands by privilege tier and deduplicates by resolved on-disk path.
5. Prints results with paths, ATT&CK technique, use case, and example command.

| Component | Location |
|---|---|
| LOLBAS catalog | `https://lolbas-project.github.io/api/lolbas.json` |
| Privilege detection | `internal/privileges` |
| MITRE technique names | `internal/mitre` |
| Path resolution & output | `main.go` |

## Project layout

```
.
├── main.go
├── internal/
│   ├── mitre/
│   │   └── names.go              # MITRE ATT&CK ID → label map
│   └── privileges/
│       ├── privileges_windows.go # Token / Administrators group checks
│       └── privileges_stub.go    # Non-Windows stub
├── go.mod
└── go.sum
```

## Disclaimer

For **authorized** security testing, lab use, and education only. Only run against systems you own or have explicit permission to assess. LOLBAS entries describe techniques that may be abused by attackers — use responsibly. The author is not responsible for misuse.

Technique data and binary metadata are sourced from the [LOLBAS Project](https://github.com/LOLBAS-Project/LOLBAS). goLoL is not affiliated with or endorsed by the LOLBAS Project.

## License

MIT
