package mitre

import "strings"

// techniqueNames maps MITRE ATT&CK IDs to sub-technique labels used in output.
var techniqueNames = map[string]string{
	"T1003":       "OS Credential Dumping",
	"T1003.001":   "LSASS Memory",
	"T1003.002":   "Security Account Manager",
	"T1003.003":   "NTDS",
	"T1027.013":   "Encrypted/Encoded File",
	"T1036":       "Masquerading",
	"T1036.005":   "Match Legitimate Name or Location",
	"T1040":       "Network Sniffing",
	"T1047":       "Windows Management Instrumentation",
	"T1048":       "Exfiltration Over Alternative Protocol",
	"T1048.003":   "Exfiltration Over Unencrypted Non-C2 Protocol",
	"T1053.002":   "At (Windows)",
	"T1053.005":   "Scheduled Task",
	"T1055":       "Process Injection",
	"T1059":       "Command and Scripting Interpreter",
	"T1059.003":   "Windows Command Shell",
	"T1070":       "Indicator Removal",
	"T1078":       "Valid Accounts",
	"T1105":       "Ingress Tool Transfer",
	"T1113":       "Screen Capture",
	"T1127":       "Trusted Developer Utilities Proxy Execution",
	"T1127.001":   "MSBuild",
	"T1127.002":   "ClickOnce",
	"T1140":       "Deobfuscate/Decode Files or Information",
	"T1187":       "Forced Authentication",
	"T1202":       "Indirect Command Execution",
	"T1216":       "System Script Proxy Execution",
	"T1216.001":   "PubPrn",
	"T1216.002":   "SyncAppvPublishingServer",
	"T1218":       "System Binary Proxy Execution",
	"T1218.001":   "Compiled HTML File",
	"T1218.002":   "Control Panel",
	"T1218.003":   "CMSTP",
	"T1218.004":   "InstallUtil",
	"T1218.005":   "Mshta",
	"T1218.007":   "Msiexec",
	"T1218.008":   "Odbcconf",
	"T1218.009":   "Regsvcs/Regasm",
	"T1218.010":   "Regsvr32",
	"T1218.011":   "Rundll32",
	"T1218.012":   "Verclsid",
	"T1218.013":   "Mavinject",
	"T1218.014":   "MMC",
	"T1218.015":   "Electron Applications",
	"T1220":       "XSL Script Processing",
	"T1485":       "Data Destruction",
	"T1543.003":   "Windows Service",
	"T1546.007":   "Netsh Helper DLL",
	"T1547":       "Boot or Logon Autostart Execution",
	"T1548.002":   "Bypass User Account Control",
	"T1552.001":   "Credentials In Files",
	"T1562":       "Impair Defenses",
	"T1562.001":   "Disable or Modify Tools",
	"T1564":       "Hide Artifacts",
	"T1564.004":   "NTFS File Attributes",
	"T1567":       "Exfiltration Over Web Service",
}

func TechniqueLabel(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "Unknown"
	}
	if name, ok := techniqueNames[id]; ok {
		return id + ": " + name
	}
	return id
}
