package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aaron-kidwell/goLoL/internal/mitre"
	"github.com/aaron-kidwell/goLoL/internal/privileges"
)

type lolbasCommand struct {
	Command     string `json:"Command"`
	Description string `json:"Description"`
	Usecase     string `json:"Usecase"`
	Category    string `json:"Category"`
	Privileges  string `json:"Privileges"`
	MitreID     string `json:"MitreID"`
}

type lolbasEntry struct {
	Name  string `json:"Name"`
	Desc  string `json:"Description"`
	Paths []struct {
		Path string `json:"Path"`
	} `json:"Full_Path"`
	Commands []lolbasCommand `json:"Commands"`
}

type lolDriverSample struct {
	Filename    string `json:"Filename"`
	Description string `json:"Description"`
	SHA256      string `json:"SHA256"`
	SHA1        string `json:"SHA1"`
	MD5         string `json:"MD5"`
}

type lolDriverCommand struct {
	Command         string `json:"Command"`
	Description     string `json:"Description"`
	Usecase         string `json:"Usecase"`
	Privileges      string `json:"Privileges"`
	OperatingSystem string `json:"OperatingSystem"`
}

type lolDriverEntry struct {
	ID                     string            `json:"Id"`
	Category               string            `json:"Category"`
	Verified               string            `json:"Verified"`
	Commands               lolDriverCommand  `json:"Commands"`
	Resources              []string          `json:"Resources"`
	KnownVulnerableSamples []lolDriverSample `json:"KnownVulnerableSamples"`
}

type localDriver struct {
	Path     string
	Filename string
	SHA256   string
}

type driverMatch struct {
	Path           string
	Filename       string
	SHA256         string
	Category       string
	Verified       string
	ID             string
	Why            string
	ExampleCommand string
	Usecase        string
	Privileges     string
	OS             string
	Resource       string
	Loaded         string
}

func resolveLocalPath(documented string) string {
	p := filepath.FromSlash(documented)
	lower := strings.ToLower(p)

	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = os.Getenv("SystemRoot")
	}
	userProfile := os.Getenv("USERPROFILE")
	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")

	switch {
	case programFilesX86 != "" && strings.HasPrefix(lower, `c:\program files (x86)`):
		p = filepath.Join(programFilesX86, p[len(`c:\program files (x86)`):])
	case programFiles != "" && strings.HasPrefix(lower, `c:\program files`):
		p = filepath.Join(programFiles, p[len(`c:\program files`):])
	case windir != "" && strings.HasPrefix(lower, `c:\windows`):
		p = filepath.Join(windir, p[len(`c:\windows`):])
	case userProfile != "" && strings.HasPrefix(lower, `c:\users\`):
		parts := strings.SplitN(p, `\`, 4)
		if len(parts) == 4 {
			p = filepath.Join(userProfile, parts[3])
		}
	}

	return filepath.Clean(p)
}

func findOnDisk(documented string) []string {
	resolved := resolveLocalPath(documented)
	if _, err := os.Stat(resolved); err == nil {
		return []string{resolved}
	}

	if strings.Contains(strings.ToLower(documented), `\windowsapps\`) {
		base := filepath.Base(resolved)
		if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
			matches, err := filepath.Glob(filepath.Join(programFiles, "WindowsApps", "*", base))
			if err == nil && len(matches) > 0 {
				return matches
			}
		}
	}

	return nil
}

func entryLocalPaths(e lolbasEntry) []string {
	var paths []string
	seen := make(map[string]struct{})
	for _, p := range e.Paths {
		for _, local := range findOnDisk(p.Path) {
			if _, ok := seen[local]; ok {
				continue
			}
			seen[local] = struct{}{}
			paths = append(paths, local)
		}
	}
	return paths
}

func requiresSystem(privileges string) bool {
	p := strings.ToLower(strings.TrimSpace(privileges))
	return p == "system"
}

func requiresAdministrator(privileges string) bool {
	if requiresSystem(privileges) {
		return false
	}

	p := strings.ToLower(strings.TrimSpace(privileges))
	switch p {
	case "", "any", "low privileges", "user":
		return false
	}

	adminMarkers := []string{
		"admin",
		"administrator",
		"dns admin",
		"backup operators",
		"sebackup",
	}
	for _, marker := range adminMarkers {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func commandVisible(privileges string, isSystem, isAdmin bool) bool {
	if requiresSystem(privileges) {
		return isSystem
	}
	if isSystem || isAdmin {
		return true
	}
	return !requiresAdministrator(privileges)
}

func primaryLocalPath(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	if len(paths) == 1 {
		return paths[0]
	}

	prefs := []string{`\system32\`, `\framework64\`, `\syswow64\`, `\framework\`}
	for _, pref := range prefs {
		for _, p := range paths {
			if strings.Contains(strings.ToLower(p), pref) {
				return p
			}
		}
	}
	return paths[0]
}

func runnableCommands(e lolbasEntry, isSystem, isAdmin bool) []lolbasCommand {
	var allowed []lolbasCommand
	for _, cmd := range e.Commands {
		if commandVisible(cmd.Privileges, isSystem, isAdmin) {
			allowed = append(allowed, cmd)
		}
	}
	return allowed
}

const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorCyan    = "\033[96m"
	colorOrange  = "\033[38;5;208m"
	colorGreen   = "\033[92m"
	colorMagenta = "\033[95m"
)

var plainMode bool

type sortMode string

const (
	sortBinary    sortMode = "binary"
	sortPrivilege sortMode = "privilege"
	sortAttack    sortMode = "attack"
)

func normalizeBinaryName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, `.\`)
	s = strings.TrimPrefix(s, `/`)
	s = strings.TrimSuffix(s, ".exe")
	return s
}

func binaryNamesMatch(entryName, query string) bool {
	return normalizeBinaryName(entryName) == normalizeBinaryName(query)
}

func displayBinaryName(query string) string {
	q := strings.TrimSpace(query)
	q = strings.TrimPrefix(q, `.\`)
	q = strings.TrimPrefix(q, `/`)
	if q == "" {
		return query
	}
	if !strings.HasSuffix(strings.ToLower(q), ".exe") {
		q += ".exe"
	}
	return q
}

func parseSortMode(raw string) (sortMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "binary", "b":
		return sortBinary, nil
	case "privilege", "priv", "p":
		return sortPrivilege, nil
	case "attack", "mitre", "a":
		return sortAttack, nil
	default:
		return "", fmt.Errorf("unknown sort %q (use binary, privilege, or attack)", raw)
	}
}

const bannerArt = `
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
`

const plainBannerArt = `
 _____ ____  _     ____  _    
/  __//  _ \/ \   /  _ \/ \   
| |  _| / \|| |   | / \|| |   
| |_//| \_/|| |_/\| \_/|| |_/\
\____\\____/\____/\____/\____/                           
`

func printBanner() {
	if plainMode {
		fmt.Print(plainBannerArt)
		fmt.Println("Author: Aaron Kidwell")
		fmt.Println(strings.Repeat("-", 48))
		fmt.Println()
		return
	}
	fmt.Printf("\n%s%s%s", colorCyan, bannerArt, colorReset)
	fmt.Printf("%sAuthor: Aaron Kidwell%s\n\n", colorGreen, colorReset)
}

type loadingBox struct {
	message string
	drawn   bool
}

func newLoadingBox(message string) *loadingBox {
	return &loadingBox{message: message}
}

func (l *loadingBox) start() {
	if plainMode {
		fmt.Printf("[*] %s\n", l.message)
		return
	}
	l.draw(false)
}

func loadingLine(done bool, message string) string {
	prefix := "..."
	if done {
		prefix = "✓"
	}
	plain := fmt.Sprintf("  %s %s", prefix, message)
	if len(plain) > 40 {
		plain = plain[:37] + "..."
	}
	return plain + strings.Repeat(" ", 40-len(plain))
}

func (l *loadingBox) draw(done bool) {
	inner := loadingLine(done, l.message)
	if done {
		inner = colorGreen + inner + colorReset
	}
	if l.drawn {
		fmt.Print("\033[3A")
	}
	l.drawn = true
	fmt.Printf("\033[2K\r  %s╭──────────────────────────────────────────╮%s\n", colorCyan, colorReset)
	fmt.Printf("\033[2K\r  %s│%s%s%s│%s\n", colorCyan, colorReset, inner, colorCyan, colorReset)
	fmt.Printf("\033[2K\r  %s╰──────────────────────────────────────────╯%s\n", colorCyan, colorReset)
}

func (l *loadingBox) setMessage(message string) {
	l.message = message
	if plainMode {
		fmt.Printf("[*] %s\n", message)
		return
	}
	l.draw(false)
}

func (l *loadingBox) finish(message string) {
	if plainMode {
		fmt.Printf("[+] %s\n\n", message)
		return
	}
	l.message = message
	l.draw(true)
	fmt.Println()
}

func helpExeName() string {
	if len(os.Args) > 0 {
		if name := filepath.Base(os.Args[0]); name != "" && name != "." {
			return name
		}
	}
	return "golol.exe"
}

func printHelp() {
	if !plainMode {
		enableVirtualTerminal()
	}
	printBanner()
	exe := helpExeName()
	if plainMode {
		fmt.Print(fmt.Sprintf(`Lists LOLBAS binaries present on this machine that match your privilege level,
with ATT&CK techniques and example commands from lolbas-project.github.io.

Privilege tiers: user, administrator (local Administrators group), and
SYSTEM (NT AUTHORITY\SYSTEM token). SYSTEM-tier techniques are shown only
when running as SYSTEM.

Usage:
  %s [flags]

Flags:
  -h, -help          Show this help
  -driver            Scan local drivers against the LOLDrivers catalog
  -plain             ASCII-only output for telnet/reverse shells
  -s, -search string Search for one binary (e.g. certutil or certutil.exe)
  -sort string       Sort results (default "binary")
                       binary     Group by binary name (A-Z)
                       privilege  Admin tier first, then user tier
                       attack     Sort by ATT&CK ID (Txxxx)

Examples:
  %s
  %s -driver
  %s -s certutil
  %s -plain
  %s -sort privilege
  %s -sort attack
  %s -h

`, exe, exe, exe, exe, exe, exe, exe, exe))
		return
	}
	fmt.Printf(`%sLists LOLBAS binaries present on this machine that match your privilege level,
with ATT&CK techniques and example commands from lolbas-project.github.io.

Privilege tiers: user, administrator (local Administrators group), and
SYSTEM (NT AUTHORITY\\SYSTEM token). SYSTEM-tier techniques are shown only
when running as SYSTEM.

%sUsage:%s
  %s [flags]

%sFlags:%s
  -h, -help          Show this help
  -driver            Scan local drivers against the LOLDrivers catalog
  -plain             ASCII-only output for telnet/reverse shells
  -s, -search string Search for one binary (e.g. certutil or certutil.exe)
  -sort string       Sort results (default "binary")
                       binary     Group by binary name (A-Z)
                       privilege  Admin tier first, then user tier
                       attack     Sort by ATT&CK ID (Txxxx)

%sExamples:%s
  %s
  %s -driver
  %s -s certutil
  %s -plain
  %s -sort privilege
  %s -sort attack
  %s -h

`, colorDim, colorBold, colorReset, exe, colorBold, colorReset, colorBold, colorReset, exe, exe, exe, exe, exe, exe, exe)
}

func fetchLOLDriversCatalog() ([]lolDriverEntry, error) {
	resp, err := http.Get("https://www.loldrivers.io/api/drivers.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	var entries []lolDriverEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func driverSearchRoots() []string {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = os.Getenv("SystemRoot")
	}
	if windir == "" {
		windir = `C:\Windows`
	}
	return []string{
		filepath.Join(windir, "System32", "drivers"),
		filepath.Join(windir, "System32", "DriverStore", "FileRepository"),
	}
}

func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func collectLocalDrivers() ([]localDriver, error) {
	var out []localDriver
	seenPaths := make(map[string]struct{})

	for _, root := range driverSearchRoots() {
		if _, err := os.Stat(root); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}

		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !strings.EqualFold(filepath.Ext(d.Name()), ".sys") {
				return nil
			}

			key := strings.ToLower(path)
			if _, ok := seenPaths[key]; ok {
				return nil
			}
			seenPaths[key] = struct{}{}

			sum, err := hashFileSHA256(path)
			if err != nil {
				return nil
			}

			out = append(out, localDriver{
				Path:     path,
				Filename: d.Name(),
				SHA256:   strings.ToLower(sum),
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func findVulnerableDrivers(catalog []lolDriverEntry, local []localDriver) []driverMatch {
	bySHA256 := make(map[string]lolDriverEntry)
	for _, entry := range catalog {
		for _, sample := range entry.KnownVulnerableSamples {
			sum := strings.ToLower(strings.TrimSpace(sample.SHA256))
			if sum == "" {
				continue
			}
			if _, exists := bySHA256[sum]; !exists {
				bySHA256[sum] = entry
			}
		}
	}

	var matches []driverMatch
	for _, d := range local {
		entry, ok := bySHA256[d.SHA256]
		if !ok {
			continue
		}
		why := strings.TrimSpace(entry.Commands.Description)
		if why == "" {
			why = firstSampleDescription(entry.KnownVulnerableSamples)
		}
		matches = append(matches, driverMatch{
			Path:           d.Path,
			Filename:       d.Filename,
			SHA256:         d.SHA256,
			Category:       entry.Category,
			Verified:       entry.Verified,
			ID:             entry.ID,
			Why:            why,
			ExampleCommand: strings.TrimSpace(entry.Commands.Command),
			Usecase:        strings.TrimSpace(entry.Commands.Usecase),
			Privileges:     strings.TrimSpace(entry.Commands.Privileges),
			OS:             strings.TrimSpace(entry.Commands.OperatingSystem),
			Resource:       firstResource(entry.Resources),
		})
	}

	sort.Slice(matches, func(i, j int) bool {
		ai := strings.ToLower(matches[i].Filename)
		aj := strings.ToLower(matches[j].Filename)
		if ai != aj {
			return ai < aj
		}
		return matches[i].Path < matches[j].Path
	})
	return matches
}

func printDriverResults(matches []driverMatch, scanned int) {
	if plainMode {
		fmt.Println(strings.Repeat("=", 62))
		fmt.Printf("Scanned drivers: %d\n", scanned)
		fmt.Printf("Matches:         %d\n", len(matches))
		fmt.Println(strings.Repeat("=", 62))
		fmt.Println()
	} else {
		fmt.Printf("  %sScanned drivers:%s %d\n", colorDim, colorReset, scanned)
		fmt.Printf("  %sMatches:%s         %d\n\n", colorDim, colorReset, len(matches))
	}
	fmt.Println("  Note: Example command comes from LOLDrivers. If the driver is already loaded,")
	fmt.Println("  skip service creation/start and interact with the existing device interface.")
	fmt.Println()

	for i, m := range matches {
		if i > 0 {
			fmt.Println()
		}
		if plainMode {
			fmt.Printf("  [%d] %s\n", i+1, m.Filename)
		} else {
			fmt.Printf("  %s╭─%s %s[%d]%s %s%s%s\n", colorCyan, colorReset, colorDim, i+1, colorReset, colorBold, m.Filename, colorReset)
		}
		printField("Path", m.Path)
		printField("SHA256", m.SHA256)
		printField("Category", m.Category)
		printField("Verified", m.Verified)
		printField("Loaded", m.Loaded)
		printField("ID", m.ID)
		if m.Why != "" {
			printField("Why", m.Why)
		}
		if m.Usecase != "" {
			printField("Use case", m.Usecase)
		}
		if m.Privileges != "" {
			printField("Privileges", m.Privileges)
		}
		if m.OS != "" {
			printField("OS", m.OS)
		}
		if m.ExampleCommand != "" {
			printField("Example", m.ExampleCommand)
		}
		if m.Resource != "" {
			printField("Source", m.Resource)
		}
		if plainMode {
			fmt.Printf("  %s\n", strings.Repeat("-", 62))
		} else {
			fmt.Printf("  %s╰%s\n", colorCyan, strings.Repeat("─", 63))
		}
	}
}

func firstResource(resources []string) string {
	for _, r := range resources {
		r = strings.TrimSpace(r)
		if r != "" {
			return r
		}
	}
	return ""
}

func firstSampleDescription(samples []lolDriverSample) string {
	for _, s := range samples {
		desc := strings.TrimSpace(s.Description)
		if desc != "" {
			return desc
		}
	}
	return ""
}

func normalizeDriverName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".sys")
	return n
}

func loadedDriverNames() map[string]struct{} {
	loaded := make(map[string]struct{})

	// service names of loaded kernel/file system drivers
	out, err := exec.Command("sc.exe", "query", "type=", "driver", "state=", "all").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			const prefix = "SERVICE_NAME:"
			if strings.HasPrefix(line, prefix) {
				name := normalizeDriverName(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
				if name != "" {
					loaded[name] = struct{}{}
				}
			}
		}
	}

	// module names currently loaded by the OS
	out, err = exec.Command("driverquery", "/fo", "csv", "/nh").Output()
	if err == nil {
		r := csv.NewReader(strings.NewReader(string(out)))
		for {
			rec, err := r.Read()
			if err != nil {
				break
			}
			if len(rec) < 1 {
				continue
			}
			name := normalizeDriverName(rec[0])
			if name != "" {
				loaded[name] = struct{}{}
			}
		}
	}
	return loaded
}

func annotateLoadedState(matches []driverMatch) {
	if runtime.GOOS != "windows" {
		for i := range matches {
			matches[i].Loaded = "unknown"
		}
		return
	}

	loaded := loadedDriverNames()
	for i := range matches {
		name := normalizeDriverName(matches[i].Filename)
		if _, ok := loaded[name]; ok {
			matches[i].Loaded = "yes"
		} else {
			matches[i].Loaded = "no"
		}
	}
}

func runDriverMode(loader *loadingBox) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("driver scan is currently supported on Windows hosts only")
	}

	loader.setMessage("Fetching LOLDrivers catalog...")
	catalog, err := fetchLOLDriversCatalog()
	if err != nil {
		return fmt.Errorf("failed to fetch LOLDrivers catalog: %w", err)
	}

	loader.setMessage("Hashing local drivers...")
	local, err := collectLocalDrivers()
	if err != nil {
		return fmt.Errorf("failed to scan local drivers: %w", err)
	}

	loader.setMessage("Matching hashes...")
	matches := findVulnerableDrivers(catalog, local)
	annotateLoadedState(matches)
	if len(matches) == 0 {
		loader.finish("No vulnerable drivers found")
		fmt.Printf("No known vulnerable LOLDrivers found on disk. Scanned %d local drivers.\n", len(local))
		return nil
	}

	loader.finish(fmt.Sprintf("Found %d vulnerable drivers", len(matches)))
	printDriverResults(matches, len(local))
	return nil
}

func privilegeDisplay(priv string) string {
	label := strings.TrimSpace(priv)
	if label == "" {
		label = "User"
	}
	if plainMode {
		return label
	}
	if requiresSystem(label) {
		return colorMagenta + label + colorReset
	}
	if requiresAdministrator(label) {
		return colorGreen + label + colorReset
	}
	return colorOrange + label + colorReset
}

type commandEntry struct {
	privilegeRaw string
	privilege    string
	attackID     string
	attack       string
	usecase      string
	command      string
	isSystemTier bool
	isAdminTier  bool
}

type listItem struct {
	name        string
	description string
	path        string
	commands    []commandEntry
}

type flatRow struct {
	binary      string
	description string
	path        string
	command     commandEntry
}

func flattenItems(items []listItem) []flatRow {
	var rows []flatRow
	for _, item := range items {
		for _, cmd := range item.commands {
			rows = append(rows, flatRow{
				binary:      item.name,
				description: item.description,
				path:        item.path,
				command:     cmd,
			})
		}
	}
	return rows
}

func sortFlatRows(rows []flatRow, mode sortMode) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch mode {
		case sortPrivilege:
			if a.command.isSystemTier != b.command.isSystemTier {
				return a.command.isSystemTier
			}
			if a.command.isAdminTier != b.command.isAdminTier {
				return a.command.isAdminTier
			}
			if a.command.privilegeRaw != b.command.privilegeRaw {
				return a.command.privilegeRaw < b.command.privilegeRaw
			}
			if a.command.attackID != b.command.attackID {
				return a.command.attackID < b.command.attackID
			}
			return strings.ToLower(a.binary) < strings.ToLower(b.binary)
		case sortAttack:
			if a.command.attackID != b.command.attackID {
				return a.command.attackID < b.command.attackID
			}
			if a.command.isAdminTier != b.command.isAdminTier {
				return a.command.isAdminTier
			}
			return strings.ToLower(a.binary) < strings.ToLower(b.binary)
		default:
			bi := strings.ToLower(a.binary)
			bj := strings.ToLower(b.binary)
			if bi != bj {
				return bi < bj
			}
			if a.command.isAdminTier != b.command.isAdminTier {
				return a.command.isAdminTier
			}
			return a.command.attackID < b.command.attackID
		}
	})
}

func sortListItems(items []listItem) {
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].name) < strings.ToLower(items[j].name)
	})
	for i := range items {
		sort.Slice(items[i].commands, func(a, b int) bool {
			ca, cb := items[i].commands[a], items[i].commands[b]
			if ca.isSystemTier != cb.isSystemTier {
				return ca.isSystemTier
			}
			if ca.isAdminTier != cb.isAdminTier {
				return ca.isAdminTier
			}
			return ca.attackID < cb.attackID
		})
	}
}

func roleLabel(isSystem, isAdmin bool) string {
	if isSystem {
		if plainMode {
			return "NT AUTHORITY\\SYSTEM"
		}
		return colorMagenta + "NT AUTHORITY\\SYSTEM" + colorReset
	}
	if isAdmin {
		if plainMode {
			return "administrator"
		}
		return colorGreen + "administrator" + colorReset
	}
	if plainMode {
		return "standard user"
	}
	return colorOrange + "standard user" + colorReset
}

func printHeader(isSystem, isAdmin bool, mode sortMode, binaries, techniques int) {
	role := roleLabel(isSystem, isAdmin)
	if plainMode {
		fmt.Println(strings.Repeat("=", 62))
		fmt.Printf("Role:        %s\n", role)
		fmt.Printf("Sort:        %s\n", mode)
		fmt.Printf("Binaries:    %d\n", binaries)
		fmt.Printf("Techniques:  %d\n", techniques)
		fmt.Println(strings.Repeat("=", 62))
		fmt.Println()
		return
	}
	fmt.Printf("  %sRole:%s        %s\n", colorDim, colorReset, role)
	fmt.Printf("  %sSort:%s        %s\n", colorDim, colorReset, mode)
	fmt.Printf("  %sBinaries:%s    %d\n", colorDim, colorReset, binaries)
	fmt.Printf("  %sTechniques:%s  %d\n\n", colorDim, colorReset, techniques)
}

func printSection(title string) {
	if plainMode {
		fmt.Printf("\n== %s ==\n\n", title)
		return
	}
	fmt.Printf("\n  %s%s\n", title, colorReset)
	fmt.Printf("  %s%s%s\n\n", colorDim, strings.Repeat("─", 62), colorReset)
}

func flatRowTitle(mode sortMode, row flatRow) string {
	switch mode {
	case sortAttack:
		id := row.command.attackID
		if id == "" {
			if plainMode {
				id = "-"
			} else {
				id = "—"
			}
		}
		if plainMode {
			return fmt.Sprintf("%s - %s", id, row.binary)
		}
		return fmt.Sprintf("%s · %s", id, row.binary)
	case sortPrivilege:
		tier := "User tier"
		switch {
		case row.command.isSystemTier:
			tier = "SYSTEM tier"
		case row.command.isAdminTier:
			tier = "Admin tier"
		}
		if plainMode {
			return fmt.Sprintf("%s - %s", tier, row.binary)
		}
		return fmt.Sprintf("%s · %s", tier, row.binary)
	default:
		return row.binary
	}
}

func printField(label, value string) {
	if plainMode {
		fmt.Printf("  %-14s %s\n", label+":", value)
		return
	}
	fmt.Printf("  %s%-14s%s %s\n", colorDim, label, colorReset, value)
}

func printDivider() {
	if plainMode {
		fmt.Printf("  %s\n", strings.Repeat("-", 62))
		return
	}
	fmt.Printf("  %s%s%s\n", colorDim, strings.Repeat("─", 62), colorReset)
}

func printFlatRows(rows []flatRow, mode sortMode) {
	var prevSection string
	for i, row := range rows {
		section := flatSectionKey(mode, row)
		if section != prevSection {
			if prevSection != "" {
				fmt.Println()
			}
			printSection(flatSectionLabel(mode, row))
			prevSection = section
		} else if i > 0 {
			fmt.Println()
		}

		if plainMode {
			fmt.Printf("  [%d] %s\n", i+1, flatRowTitle(mode, row))
		} else {
			fmt.Printf("  %s╭─%s %s[%d]%s %s%s%s\n", colorCyan, colorReset, colorDim, i+1, colorReset, colorBold, flatRowTitle(mode, row), colorReset)
		}
		printField("Path", row.path)
		printField("Description", row.description)
		printDivider()
		printField("Privileges", row.command.privilege)
		printField("ATT&CK", row.command.attack)
		printField("Use case", row.command.usecase)
		printField("Command", row.command.command)
		if plainMode {
			fmt.Printf("  %s\n", strings.Repeat("-", 62))
		} else {
			fmt.Printf("  %s╰%s\n", colorCyan, strings.Repeat("─", 63))
		}
	}
}

func flatSectionKey(mode sortMode, row flatRow) string {
	switch mode {
	case sortAttack:
		return row.command.attackID
	case sortPrivilege:
		switch {
		case row.command.isSystemTier:
			return "system"
		case row.command.isAdminTier:
			return "admin"
		default:
			return "user"
		}
	default:
		return ""
	}
}

func flatSectionLabel(mode sortMode, row flatRow) string {
	switch mode {
	case sortAttack:
		label := row.command.attack
		if label == "" {
			label = row.command.attackID
		}
		if label == "" {
			label = "Unknown technique"
		}
		if plainMode {
			return label
		}
		return colorBold + label + colorReset
	case sortPrivilege:
		switch {
		case row.command.isSystemTier:
			if plainMode {
				return "SYSTEM tier"
			}
			return colorBold + colorMagenta + "SYSTEM tier" + colorReset
		case row.command.isAdminTier:
			if plainMode {
				return "Administrator tier"
			}
			return colorBold + colorGreen + "Administrator tier" + colorReset
		default:
			if plainMode {
				return "User tier"
			}
			return colorBold + colorOrange + "User tier" + colorReset
		}
	default:
		return ""
	}
}

func printGroupedItems(items []listItem) {
	for i, item := range items {
		if i > 0 {
			fmt.Println()
		}
		if plainMode {
			fmt.Printf("  [%d] %s\n", i+1, item.name)
		} else {
			fmt.Printf("  %s╭─%s %s[%d]%s %s%s%s\n", colorCyan, colorReset, colorDim, i+1, colorReset, colorBold, item.name, colorReset)
		}
		printField("Path", item.path)
		printField("Description", item.description)

		for j, cmd := range item.commands {
			if plainMode {
				fmt.Printf("  -- technique %d\n", j+1)
			} else {
				fmt.Printf("  %s├─ technique %d%s\n", colorCyan, j+1, colorReset)
			}
			printField("Privileges", cmd.privilege)
			printField("ATT&CK", cmd.attack)
			printField("Use case", cmd.usecase)
			printField("Command", cmd.command)
		}
		if plainMode {
			fmt.Printf("  %s\n", strings.Repeat("-", 62))
		} else {
			fmt.Printf("  %s╰%s\n", colorCyan, strings.Repeat("─", 63))
		}
	}
}

func printResults(items []listItem, isSystem, isAdmin bool, mode sortMode) {
	if !plainMode {
		enableVirtualTerminal()
	}

	techniques := 0
	for _, item := range items {
		techniques += len(item.commands)
	}
	printHeader(isSystem, isAdmin, mode, len(items), techniques)

	if mode == sortBinary {
		printGroupedItems(items)
		return
	}

	rows := flattenItems(items)
	sortFlatRows(rows, mode)
	printFlatRows(rows, mode)
}

func enableVirtualTerminal() {
	if runtime.GOOS != "windows" {
		return
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")

	handle := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	r, _, _ := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return
	}

	const enableVirtualTerminalProcessing = 0x0004
	_, _, _ = setConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
}

func main() {
	help := flag.Bool("h", false, "show help")
	helpLong := flag.Bool("help", false, "show help")
	driverFlag := flag.Bool("driver", false, "scan local drivers against the LOLDrivers catalog")
	plainFlag := flag.Bool("plain", false, "ASCII-only output for telnet/reverse shells")
	var searchQuery string
	flag.StringVar(&searchQuery, "s", "", "search for a specific binary by name")
	flag.StringVar(&searchQuery, "search", "", "search for a specific binary by name")
	sortFlag := flag.String("sort", "binary", "sort by: binary, privilege, attack")
	flag.Parse()

	plainMode = *plainFlag
	searchQuery = strings.TrimSpace(searchQuery)

	if *help || *helpLong {
		printHelp()
		return
	}

	sortMode, err := parseSortMode(*sortFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		printHelp()
		os.Exit(2)
	}
	if *driverFlag {
		if searchQuery != "" {
			fmt.Fprintln(os.Stderr, "-driver cannot be combined with -s/-search")
			os.Exit(2)
		}
		if sortMode != sortBinary {
			fmt.Fprintln(os.Stderr, "-driver does not support -sort (only default binary mode)")
			os.Exit(2)
		}
	}

	if !plainMode {
		enableVirtualTerminal()
	}
	printBanner()

	loader := newLoadingBox("Checking privileges...")
	loader.start()

	if *driverFlag {
		if err := runDriverMode(loader); err != nil {
			loader.finish("Failed")
			fmt.Println(err)
		}
		return
	}

	loader.setMessage("Checking process token...")
	isSystem, err := privileges.IsLocalSystem()
	if err != nil {
		loader.finish("Failed")
		fmt.Println("Failed to check process token:", err)
		return
	}

	loader.setMessage("Checking local group membership...")
	isAdmin, err := privileges.IsLocalAdministrator()
	if err != nil {
		loader.finish("Failed")
		fmt.Println("Failed to check local group membership:", err)
		return
	}

	loader.setMessage("Fetching LOLBAS catalog...")
	resp, err := http.Get("https://lolbas-project.github.io/api/lolbas.json")
	if err != nil {
		loader.finish("Failed")
		fmt.Println("Failed to fetch LOLBAS list:", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		loader.finish("Failed")
		fmt.Println("Unexpected status:", resp.Status)
		return
	}

	loader.setMessage("Parsing LOLBAS catalog...")
	var entries []lolbasEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		loader.finish("Failed")
		fmt.Println("Failed to parse JSON:", err)
		return
	}

	if searchQuery != "" {
		loader.setMessage(fmt.Sprintf("Searching for %s...", displayBinaryName(searchQuery)))
	} else {
		loader.setMessage("Scanning local binaries...")
	}
	seenPaths := make(map[string]struct{})
	var items []listItem
	for i, e := range entries {
		if searchQuery != "" && !binaryNamesMatch(e.Name, searchQuery) {
			continue
		}

		if searchQuery == "" && i > 0 && i%40 == 0 {
			loader.setMessage(fmt.Sprintf("Scanning local binaries... (%d/%d)", i, len(entries)))
		}

		paths := entryLocalPaths(e)
		path := primaryLocalPath(paths)
		if path == "" {
			if searchQuery != "" {
				loader.finish("Not found")
				fmt.Printf("%s is not available on disk.\n", displayBinaryName(searchQuery))
				return
			}
			continue
		}

		pathKey := strings.ToLower(path)
		if _, ok := seenPaths[pathKey]; ok {
			continue
		}

		commands := runnableCommands(e, isSystem, isAdmin)
		if len(commands) == 0 {
			if searchQuery != "" {
				loader.finish("No techniques")
				fmt.Printf("%s is on disk at %s but no techniques are available at your privilege level.\n", e.Name, path)
				return
			}
			continue
		}

		sort.Slice(commands, func(i, j int) bool {
			sysI := requiresSystem(commands[i].Privileges)
			sysJ := requiresSystem(commands[j].Privileges)
			if sysI != sysJ {
				return sysI
			}
			adminI := requiresAdministrator(commands[i].Privileges)
			adminJ := requiresAdministrator(commands[j].Privileges)
			if adminI != adminJ {
				return adminI
			}
			return commands[i].MitreID < commands[j].MitreID
		})

		seenPaths[pathKey] = struct{}{}

		commandEntries := make([]commandEntry, 0, len(commands))
		for _, cmd := range commands {
			privRaw := strings.TrimSpace(cmd.Privileges)
			if privRaw == "" {
				privRaw = "User"
			}
			commandEntries = append(commandEntries, commandEntry{
				privilegeRaw: privRaw,
				privilege:    privilegeDisplay(cmd.Privileges),
				attackID:     strings.TrimSpace(cmd.MitreID),
				attack:       mitre.TechniqueLabel(cmd.MitreID),
				usecase:      cmd.Usecase,
				command:      cmd.Command,
				isSystemTier: requiresSystem(cmd.Privileges),
				isAdminTier:  requiresAdministrator(cmd.Privileges),
			})
		}

		items = append(items, listItem{
			name:        e.Name,
			description: e.Desc,
			path:        path,
			commands:    commandEntries,
		})
	}

	if len(items) == 0 {
		if searchQuery != "" {
			loader.finish("Not found")
			fmt.Printf("%s is not available on disk.\n", displayBinaryName(searchQuery))
			return
		}
		loader.finish("No runnable binaries found")
		fmt.Println("No runnable LOLBAS binaries found on this host.")
		return
	}

	loader.finish(fmt.Sprintf("Found %d binaries, %d techniques", len(items), countTechniques(items)))

	sortListItems(items)
	printResults(items, isSystem, isAdmin, sortMode)
}

func countTechniques(items []listItem) int {
	n := 0
	for _, item := range items {
		n += len(item.commands)
	}
	return n
}
