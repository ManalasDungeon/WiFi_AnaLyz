# WifiAnalyzerPro

**Real-time Wi-Fi analysis and security monitoring for Windows**

![.NET](https://img.shields.io/badge/.NET-6%2B-512BD4?logo=dotnet)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?logo=windows)
![Npcap](https://img.shields.io/badge/Npcap-1.70%2B-00B4D8)
![License](https://img.shields.io/badge/license-MIT-green)

---

WifiAnalyzerPro is a Windows console application that combines active WLAN scanning, passive 802.11 frame capture, and full-featured security analysis in one package. It works equally well for home use (network optimization) and enterprise environments (WIPS-level threat detection).

---

## Features

### 📡 Network Analysis
- **Real-time scanning** — Windows WLAN API with adaptive scan intervals
- **Passive capture** — SharpPcap/Npcap captures Beacon, Probe, Deauth, RTS/CTS and Data frames
- **Interference scoring** — co-channel + adjacent penalty weighted by BSS Load IE 11
- **PHY capabilities** — Wi-Fi 4/5/6/6E/7, MIMO streams, channel width, SNR
- **Roaming standards** — 802.11k/v/r parsed from beacon frames
- **ARP scan** — discovers device IP, MAC, hostname and vendor

### 🔒 Security Detection
- **Evil Twin detection** — OUI comparison + security downgrade + PMF cross-check (3 confidence levels)
- **Deauth storm detection** — sliding 10 s window, broadcast alert, reason code fingerprinting (aireplay-ng, mdk3/4)
- **PMF cross-check** — MFPR=1 + unprotected frame = confirmed attack
- **PMKID harvesting detection** — behavioral: >3 APs / 60 s matches hcxdumptool pattern (no cryptographic parsing)
- **DPI** — DNS queries and TLS SNI names captured from open networks

### 🧠 Behavioral IDS
- **24-hour baseline** per device, 7-day ring buffer
- **5 anomaly rules**: `TRAFFIC_SPIKE`, `NIGHT_ACTIVITY`, `ARP_SWEEP`, `DNS_EXPLOSION`, `DATA_EXFIL`
- **Automatic alerting** via Discord/Slack webhooks

### 🍯 Honeypot
- **Probe Request trap** — passive decoy SSID monitoring
- **Optional SoftAP** — Windows Hosted Network (netsh)
- **Zero false positives** — every hit is intentional

### 🔍 Threat Intelligence
- **AlienVault OTX** — automatic lookup for unknown domains
- **AbuseIPDB** — IP address reputation check
- **L1 memory cache** with 24 h TTL + rate limiter + in-flight deduplication
- **Automatic containment** — Malicious result → RouterContainment → MAC block in seconds

### 📋 Compliance Reporting
- **PCI-DSS 4.0** — 6 rules (WEP ban, PMF enforcement, rogue AP, WPA3 adoption rate...)
- **ISO 27001:2022** — 4 rules (channel load, signal quality, EAPOL detection...)
- **HTML report** — dark theme, Pass/Fail/Warning badges, overall grade A–F
- **Press `C`** — generates report instantly

### 🌐 Integrations
| Integration | Function |
|---|---|
| Discord / Slack | Webhook alerts with rich embeds |
| Unifi Network | `block-sta` REST API |
| pfSense | Firewall alias REST API |
| OPNsense | Alias + reconfigure |
| Prometheus | `/metrics` endpoint |

### 🔬 Forensics
- **Automatic PCAP recording** — triggered by Evil Twin / Deauth attack / Honeypot events
- **libpcap format** — opens directly in Wireshark, link type 127 (802.11 + radiotap)
- **MAC filtering** — captures only the triggering device's traffic

---

## Screenshot

```
╔════════════════════════════════════════════════════════════════════╗
║ WifiAnalyzerPro v4.0  |  Ctrl+C to quit                           ║
║ RSSI scan [■□□]  Passive: 14 APs  |  Web: localhost:8765          ║
║ Best 2.4 GHz: CH 11 (free)  |  Interference: 4.2  |  Ping: 12 ms ║
║────────────────────────────────────────────────────────────────────║
║ SSID              CH  BAND   ████████  RSSI  Q INT   Vendor  Score║
║ ►HomeNetwork       6  2.4G   ████████   -52  A  2.1  TP-Link  87.3║
║  GuestWifi         6  2.4G   ██████░░   -65  B  5.8  Asus     71.2║
║  Neighbor_5G      36   5 G   ████░░░░   -72  C  0.0  Intel    64.8║
║ [D] ARP found 8 devices:                                           ║
║    192.168.1.1      AA:BB:CC:11:22:33   [ARP]                      ║
║    ↳ router.lan | TP-Link Technologies                             ║
╚════════════════════════════════════════════════════════════════════╝
```

---

## Installation

### Requirements

| Component | Version |
|---|---|
| Windows | 10 build 1903+ or Windows 11 |
| .NET SDK | 6.0+ |
| [Npcap](https://npcap.com) | 1.70+ |

> **Windows 11 24H2+**: Settings → Privacy → Location → On

### 1. Clone

```bash
git clone https://github.com/your-username/WifiAnalyzerPro.git
cd WifiAnalyzerPro
```

### 2. Build

```bash
dotnet build -c Release
```

### 3. Run (as Administrator)

```bash
# Packet capture requires elevated privileges
dotnet run -c Release
```

Or right-click the compiled `.exe` → **Run as administrator**.

---

## Configuration

The app creates `wifi_config.json` automatically on first run. Changes take effect **immediately** — no restart needed.

```jsonc
{
  // Scanning
  "MinScanIntervalSeconds": 12,
  "StaleApMinutes": 5,

  // Alerts
  "RssiAlertThreshold": -80,
  "RssiAlertClearThreshold": -75,
  "AlertCooldownSeconds": 60,

  // Discord / Slack (optional)
  "DiscordWebhookUrl": "https://discord.com/api/webhooks/...",
  "SlackWebhookUrl": "https://hooks.slack.com/services/...",

  // Threat Intelligence (optional)
  "EnableThreatIntel": false,
  "OtxApiKey": "",
  "AbuseIpDbApiKey": "",

  // Forensic PCAP recording (optional)
  "EnableAutoCapture": false,
  "CaptureDirectory": "captures",
  "CaptureDurationSeconds": 60,

  // Honeypot (optional)
  "HoneypotSsids": [],
  "EnableHoneypotSoftAp": false,

  // Router containment (optional)
  "UnifiControllerUrl": "",
  "UnifiUsername": "",
  "UnifiPassword": "",
  "PfSenseUrl": "",
  "OPNsenseUrl": ""
}
```

### OUI Database (optional)

Download vendor data for accurate device identification:

```bash
curl -o oui.csv "https://maclookup.app/downloads/csv-database/get-db"
```

### Custom Blacklist

Create `blacklist.txt` in the same directory:

```
# One domain per line: domain [TAB severity 1-3 [TAB reason]]
evil-domain.com    3    Known C2 infrastructure
tracker.internal   1    Internal tracking
```

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `S` | Force immediate scan |
| `R` | Reset traffic counters |
| `E` | Export reports (JSON / CSV / HTML) |
| `C` | Generate compliance report (PCI-DSS / ISO 27001) |
| `D` | ARP scan — shows IP, MAC, hostname, vendor |
| `A` | Alert history view |
| `X` | 2.4 GHz spectrum view |
| `F` | SSID filter |
| `Tab` | Cycle sort mode |
| `↑` / `↓` | Select AP |
| `Enter` | AP detail view (PHY, roaming, PMF, ping, deauth history...) |
| `Q` | WiFi QR code for selected AP |
| `Esc` | Close / cancel |
| `Ctrl+C` | Quit |

---

## Web Dashboard

Open in browser: **http://localhost:8765**

- Real-time SSE updates (~4 s)
- Top Services pie chart (DPI)
- Network activity timeline (60 s)
- Deauth attack timeline
- Evil Twin, Honeypot, EAPOL, PCAP and RouterBlock panels

---

## Enabling Security Features

### Threat Intelligence (OTX + AbuseIPDB)

1. Register at [AlienVault OTX](https://otx.alienvault.com) (free)
2. Register at [AbuseIPDB](https://www.abuseipdb.com) (free, 1,000 queries/day)
3. Add keys to `wifi_config.json`:

```jsonc
"EnableThreatIntel": true,
"OtxApiKey": "your-otx-key",
"AbuseIpDbApiKey": "your-abuseipdb-key"
```

### Router Containment (Unifi)

```jsonc
"UnifiControllerUrl": "https://192.168.1.1:8443",
"UnifiUsername": "admin",
"UnifiPassword": "password",
"UnifiSite": "default"
```

### Automatic PCAP Forensics

```jsonc
"EnableAutoCapture": true,
"CaptureDirectory": "captures",
"CaptureDurationSeconds": 60
```

Files open directly in Wireshark.

---

## Architecture

```
WifiAnalyzerEngine          PassiveChannelScanner (Npcap)
  ├── AlertManager            ├── DeauthTracker
  ├── ChannelAnalyzer         ├── FrameCapabilityParser
  ├── ChannelLoadTracker      ├── HiddenNodeTracker → DpiAnalyzer
  ├── BehaviorProfiler        ├── EapolTracker
  ├── ThreatIntelClient       └── WifiHoneypot
  ├── SecurityAlertDispatcher
  ├── RouterContainment
  ├── PcapRecorder
  └── ReportExporter → ComplianceChecker

WebDashboard (HttpListener + SSE)
Program.cs (console UI, keyboard input, main loop)
```

---

## NuGet Dependencies

| Package | Purpose |
|---|---|
| `ManagedNativeWifi` 2.x | Windows WLAN API wrapper |
| `SharpPcap` 6.x | Npcap packet capture |

Everything else uses the .NET standard library — no unnecessary dependencies.

---

## File Structure

```
WifiAnalyzerPro/
├── AlertManager.cs          Alerts, cooldown, webhook dispatch
├── BehaviorProfiler.cs      Behavioral IDS, 24h baseline, ring buffer
├── ChannelAnalyzer.cs       Interference scoring, band detection
├── ChannelLoadTracker.cs    BSS Load IE 11 tracking
├── ComplianceChecker.cs     PCI-DSS 4.0 + ISO 27001 rules
├── CsvHelper.cs             RFC-4180 CSV escaping
├── DeauthTracker.cs         Deauth storm + PMF cross-check
├── DeviceScanner.cs         ARP scan + mDNS listener
├── DpiAnalyzer.cs           35 services + blacklist 35+ entries
├── EapolTracker.cs          PMKID harvesting pattern (behavioral)
├── FrameCapabilityParser.cs HT/VHT/HE/EHT IE parsing
├── HiddenNodeTracker.cs     RTS/CTS + DNS/TLS SNI capture
├── ILogger.cs               Logging abstraction (File/Debug)
├── LongTermExporter.cs      Append-only CSV for long-term tracking
├── Models.cs                All data types
├── OuiDatabase.cs           MAC vendor lookup
├── PassiveChannelScanner.cs Npcap 802.11 frame parsing
├── PcapRecorder.cs          libpcap forensic recording
├── Program.cs               Main loop, console UI, key handling
├── ReportExporter.cs        HTML/CSS/JS/CSV/Prometheus/Compliance
├── RouterContainment.cs     Unifi/pfSense/OPNsense REST API
├── SecurityAlertDispatcher.cs Discord/Slack/Generic webhooks
├── SignalChartRenderer.cs   ASCII charts (spectrum, ping, rhythm)
├── SignalStats.cs           Ring buffer + Welford online + EMA
├── SpeedMonitor.cs          Ping + streaming throughput test
├── ThreatIntelClient.cs     OTX + AbuseIPDB + cache + rate limiter
├── WebDashboard.cs          HTTP/SSE server, DashboardData
├── WifiAnalyzerEngine.cs    Core engine, orchestration
├── WifiConfig.cs            Configuration + validation + hot-reload
├── WifiConfigWatcher.cs     FileSystemWatcher with debounce
├── WifiHoneypot.cs          Probe Request trap + SoftAP
└── WifiQrCode.cs            QR code generator (Reed-Solomon, no deps)
```

---

## Security & Legal

- **Passive capture** is legal on networks you own or have explicit permission to monitor.
- **Honeypot SoftAP** — use only in controlled environments you administer.
- **RouterContainment** — works only against infrastructure you own.
- **Detecting** deauth attacks is legal. **Sending** them is illegal in almost every jurisdiction.
- This tool is intended for network administrators, security researchers and home users on their own networks.

---

## License

MIT — see [LICENSE](LICENSE)

---

*~9,500 lines of C# · 30 files · .NET 6+ · SharpPcap · ManagedNativeWifi*
