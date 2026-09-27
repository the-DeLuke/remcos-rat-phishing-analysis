# Phishing Email & Malware Incident Report
### Remcos RAT Delivered via Spoofed Purchase-Order Phishing Email

**Analyst:** M N Pareed Noubinsha  
**Date of Analysis:** September 6, 2026  
**Classification:** TLP:CLEAR — Educational / Portfolio Project  
**Source Sample:** Public sample courtesy of [malware-traffic-analysis.net](https://malware-traffic-analysis.net) (2026-08-06)

---

## 1. Executive Summary

On July 30, 2026, a phishing email impersonating a purchase-order notification (“PO-MQ22-141701”) was sent from a spoofed sender, “Susan Liu” (susanliu@beeflex.us). The email contained a link that, after passing through a fake Google OAuth redirect designed to appear legitimate, led the recipient to download a password-less RAR archive from `beeflex.online`. Inside the archive was a heavily obfuscated JavaScript file which, when executed, dropped and launched a PowerShell script that installed the Remcos Remote Access Trojan (RAT), version 7.2.5 Pro.

The malware established persistence through both a Windows Registry Run key and a Startup folder shortcut, then began beaconing to a command-and-control (C2) server at `onboard.radiantfluxstudio.com` (185.14.92.102) over port 443. Multi-source analysis (VirusTotal community detections, crowdsourced YARA/Sigma rules, and passive DNS/file relationship data) confirms this C2 infrastructure has hosted at least 11 distinct malicious payloads since July 2026, indicating an active, ongoing campaign rather than an isolated incident.

---

## 2. Incident Timeline

| Date/Time (UTC) | Event |
|---|---|
| 2026-07-29 20:11 (-07:00) | Phishing email sent from spoofed sender "Susan Liu" \<susanliu@beeflex.us\> |
| 2026-07-30 03:11–03:13 | Email passes through relay host.colocrossing.com |
| 2026-07-30 | Email delivered; malicious link points to fake Google OAuth redirect → beeflex.online |
| 2026-07-30 (assumed click) | RAR archive PO-MQ22-141701.rar downloaded from beeflex.online |
| 2026-07-30 (assumed execution) | Embedded JavaScript (PO-MQ22-141701.js) executed, dropping PowerShell payload |
| 2026-07-30 (assumed) | Remcos RAT installed; persistence set via Registry Run key and Startup folder |
| 2026-08-06 02:41 | Malicious link confirmed still active/serving malware during follow-up analysis |

---

## 3. Technical Analysis

### 3.1 Delivery Chain

Phishing email → malicious link → fake Google OAuth consent redirect → beeflex.online → RAR archive download → extracted .js file → PowerShell dropper → Remcos RAT.

The fake OAuth redirect step is a social-engineering technique intended to make the link appear to originate from a trusted Google sign-in flow, increasing the likelihood a recipient will proceed.

### 3.2 Email Header Analysis

| Field | Value |
|---|---|
| From | "Susan Liu" \<susanliu@beeflex.us\> |
| Subject | PO-MQ22-141701 |
| Date | 29 Jul 2026 20:11:45 -0700 |
| Relay | host.colocrossing.com (107.173.19.19) |
| Originating IP | 104.37.175.115 |

The sender domain (beeflex.us) does not match the domain hosting the payload (beeflex.online) or the final C2 (radiantfluxstudio.com) — a common indicator of spoofed or throwaway sending infrastructure distinct from attacker-controlled hosting.

### 3.3 Malicious File Details

| Stage | Filename | SHA-256 | Type |
|---|---|---|---|
| Dropper | PO-MQ22-141701.js | `aed597f019da518a072be2ed666d37176f4dc7a4534411f5ecded9022e8da173` | Obfuscated JavaScript (4.96 MB) |
| Persistent payload | ps_nvczOdIRonsJ_...ps1 | `dab9728645297b54e009e683fa670d5bf0b15aa3f69d4b9b3b53210ee9653183` | PowerShell script |

VirusTotal flagged the JavaScript dropper as malicious by 9 of 61 vendors — a relatively low detection rate consistent with heavy obfuscation. A crowdsourced YARA rule (`Base64_Encoded_Powershell_Directives`) confirmed the file contains base64-encoded PowerShell commands. VirusTotal's automated classifier labeled the sample "trojan.formbook/powershell," while independent crowdsourced Sigma rules and documented behavior confirm the final payload is Remcos RAT — suggesting either a multi-payload dropper chain or a variant not yet reflected in the automated family classifier.

### 3.4 Persistence Mechanisms

- **Registry Run Key:** `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` → value `SystemUpdate_ps_nvczOdIRonsJ_1785981685990` launching the PowerShell payload with `-ExecutionPolicy Bypass -WindowStyle Hidden`.
- **Startup Folder Shortcut:** `C:\Users\[username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\SystemUpdate_ps_nvczOdIRonsJ_1785981685990.lnk`
- Both mechanisms were independently confirmed by crowdsourced Sigma rule matches on VirusTotal ("New RUN Key Pointing to Suspicious Folder" and "Startup Folder File Write").

### 3.5 Command-and-Control Infrastructure

| Indicator | Detail |
|---|---|
| C2 domain | onboard.radiantfluxstudio.com |
| C2 IP (at infection time) | 185.14.92.102 : 443 |
| Detection rate | 18 / 90 vendors (VirusTotal), labeled Malicious / Phishing / Malware |
| Domain age | ~7 months (registered via Realtime Register B.V.) |
| Sibling domain | onboarding.radiantfluxstudio.com (12/90 detections) |
| Additional resolved IPs | 194.15.36.34, 64.89.160.127 (infrastructure rotation) |

Two crowdsourced IDS rules matched this traffic pattern with High severity: "ET MALWARE Remcos 3.x Unencrypted Checkin" and "ET MALWARE Remcos 3.x Unencrypted Server Response," confirming the C2 protocol signature as Remcos rather than a generic downloader.

VirusTotal's file-relationship data shows the exact dropper directly communicated with this domain, and that the same infrastructure has served at least 11 distinct payloads (PowerShell scripts and Win32 executables) between July and September 2026 — evidence this is an active campaign with multiple victims.

---

## 4. Indicators of Compromise (IOCs)

| Type | Indicator |
|---|---|
| Sender email | susanliu@beeflex.us |
| Payload hosting domain | beeflex.online |
| RAR archive (SHA-256) | `59ca745f5c6f9b9ea607edd61204810acd0afaf932764fa286cc8ee3bcedb79d` |
| JS dropper (SHA-256) | `aed597f019da518a072be2ed666d37176f4dc7a4534411f5ecded9022e8da173` |
| PowerShell payload (SHA-256) | `dab9728645297b54e009e683fa670d5bf0b15aa3f69d4b9b3b53210ee9653183` |
| C2 domain | onboard.radiantfluxstudio.com |
| C2 IP | 185.14.92.102 (port 443) |
| Sibling domain | onboarding.radiantfluxstudio.com |

> Also available in machine-readable form: [`IOCs.csv`](./IOCs.csv)

---

## 5. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Observed Behavior |
|---|---|---|
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | Phishing: Spearphishing Link | Malicious link embedded in a spoofed purchase-order email |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User Execution: Malicious File | Victim extracts and runs the JavaScript dropper from the RAR archive |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | JavaScript dropper launches an obfuscated, base64-encoded PowerShell script |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart: Registry Run Keys / Startup Folder | Persistence set via both a Registry Run key and a Startup folder shortcut |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Application Layer Protocol: Web Protocols | Remcos C2 beaconing over HTTPS (port 443) |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Base64-encoded PowerShell directives inside the JavaScript dropper |

---

## 6. Impact Assessment

Remcos is a full-featured commercial Remote Access Trojan providing an attacker with remote desktop control, keystroke logging, screen/webcam/microphone capture, file exfiltration, and the ability to deploy additional payloads. A successful infection would grant the threat actor persistent, hands-on-keyboard access to the victim host, with potential for credential theft, lateral movement, and further compromise of connected systems or accounts.

Because persistence is established through two independent mechanisms (registry and startup folder), the infection would survive a standard reboot and require targeted remediation rather than a simple process kill.

---

## 7. Recommended Remediation & Detection Opportunities

- Block the identified domain (`onboard.radiantfluxstudio.com`), its sibling, and associated IPs at the perimeter firewall / DNS filtering layer.
- Alert on outbound HTTPS traffic matching the ET MALWARE Remcos 3.x checkin/response signatures.
- Hunt for the specific registry Run key and Startup folder artifact patterns (`SystemUpdate_ps_*`) across the environment.
- Flag inbound emails where the sender's display domain and the linked/redirect domain differ (beeflex.us vs. beeflex.online vs. radiantfluxstudio.com) as a phishing heuristic.
- Detect and alert on PowerShell invoked with `-ExecutionPolicy Bypass -WindowStyle Hidden`, particularly when the parent process is a script interpreter (wscript.exe/cscript.exe) rather than an interactive user session.
- **User awareness:** purchase-order and invoice-themed phishing remains a common lure; reinforce verification of unexpected PO/invoice emails through a secondary channel.

---

## 8. Supporting Evidence

**Figure 1** — VirusTotal detection results for the JavaScript dropper, showing crowdsourced YARA and Sigma rule matches confirming Remcos RAT behavior.
![VT JS Dropper](./screenshots/fig1-vt-js-dropper.png)

**Figure 2** — VirusTotal domain reputation for the C2 domain — 18/90 vendors flagged it as malicious/phishing.
![VT C2 Domain](./screenshots/fig2-vt-c2-domain.png)

**Figure 3** — Passive DNS replication and communicating files linked to the C2 domain.
![Passive DNS](./screenshots/fig3-passive-dns.png)

**Figure 4** — Extended list of malicious files observed communicating with the same C2 infrastructure.
![Communicating Files](./screenshots/fig4-communicating-files.png)

**Figure 5** — VirusTotal relationship graph summarizing the domain's connections.
![Relationship Graph](./screenshots/fig5-relationship-graph.png)

---

## 9. Sources & Tools Used

- Sample and incident notes: [malware-traffic-analysis.net](https://malware-traffic-analysis.net) (2026-08-06 entry)
- File and domain reputation, YARA/Sigma/IDS rule matching, passive DNS and file-relationship data: [VirusTotal](https://www.virustotal.com)
- Sandbox cross-reference attempt: [Hybrid Analysis](https://www.hybrid-analysis.com)
- Framework reference: [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

---

*This report was created for educational/portfolio purposes based on a publicly shared malware sample. No proprietary or confidential data is included.*
