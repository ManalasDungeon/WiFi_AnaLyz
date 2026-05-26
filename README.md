[README.md](https://github.com/user-attachments/files/28271134/README.md)
# WifiAnalyzerPro

**Reaaliaikainen Wi-Fi-analysointi- ja tietoturvajärjestelmä Windowsille**

![.NET](https://img.shields.io/badge/.NET-6%2B-512BD4?logo=dotnet)
![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D4?logo=windows)
![Npcap](https://img.shields.io/badge/Npcap-1.70%2B-00B4D8)
![License](https://img.shields.io/badge/license-MIT-green)

---

WifiAnalyzerPro on Windows-komentorivisovellus joka yhdistää aktiivisen WLAN-skannauksen, passiivisen 802.11-kaappauksen ja täysimittaisen tietoturva-analyysin yhteen pakettiin. Se toimii sekä kotikäytössä verkkojen optimointiin että yrityskäytössä WIPS-tasoiseen uhkientunnistukseen.

---

## Ominaisuudet

### 📡 Verkon analysointi
- **Reaaliaikainen skannaus** — Windows WLAN API + adaptiivinen skannausväli
- **Passiivinen kaappaus** — SharpPcap/Npcap kaappaa Beacon, Probe, Deauth, RTS/CTS ja Data-kehykset
- **Häiriöpisteytys** — co-channel + adjacent penalty + BSS Load IE 11 -kerroin
- **PHY-kyvykkyydet** — Wi-Fi 4/5/6/6E/7, MIMO-virrat, kaistanleveys, SNR
- **Roaming-standardit** — 802.11k/v/r beacon-kentistä
- **ARP-skannaus** — laitteiden IP, MAC, hostname ja valmistaja

### 🔒 Tietoturva
- **Evil Twin -tunnistus** — OUI-vertailu + tietoturvatason lasku + PMF-ristikäyttö (3 luottamustasoa)
- **Deauth-myrskytunnistus** — liukuva 10 s ikkuna, broadcast-hälytys, reason code -sormenjälki (aireplay-ng, mdk3/4)
- **PMF-ristikäyttö** — MFPR=1 + salaamaton kehys = varmennettu hyökkäys
- **PMKID-keräilytunnistus** — behavioral: >3 AP / 60 s = hcxdumptool-malli (ei kryptografista parsintaa)
- **DPI** — DNS-kyselyiden ja TLS SNI -nimien kaappaus avoimista verkoista

### 🧠 Behavioral IDS
- **24 h baseline** per laite, 7 vrk ring buffer
- **5 anomaliasääntöä**: `TRAFFIC_SPIKE`, `NIGHT_ACTIVITY`, `ARP_SWEEP`, `DNS_EXPLOSION`, `DATA_EXFIL`
- **Automaattinen hälytys** Discord/Slack-webhookilla

### 🍯 Honeypot
- **Probe Request -ansa** — passiivinen decoy-SSID-kuuntelu
- **Valinnainen SoftAP** — Windows Hosted Network (netsh)
- **Nolla väärää positiivista** — jokainen osuma on tahallinen

### 🔍 Uhkatiedustelu (Threat Intelligence)
- **AlienVault OTX** — tuntemattomien domainien automaattinen tarkistus
- **AbuseIPDB** — IP-osoitteiden mainehaku
- **L1-muisticache** 24 h TTL + rate limiter + in-flight deduplication
- **Automaattinen eristys** — Malicious-löydös → RouterContainment → MAC-esto sekunnissa

### 📋 Compliance
- **PCI-DSS 4.0** — 6 sääntöä (WEP-kielto, PMF, rogue AP, WPA3-käyttöaste...)
- **ISO 27001:2022** — 4 sääntöä (kanavakuorma, signaali, EAPOL-tunnistus...)
- **HTML-raportti** — tumma teema, Pass/Fail/Warning-badget, kokonaisarvosana A–F
- **Näppäin `C`** — generoi raportin välittömästi

### 🌐 Integraatiot
| Integraatio | Toiminto |
|---|---|
| Discord / Slack | Webhook-hälytykset rich embed -muodossa |
| Unifi Network | `block-sta` REST API |
| pfSense | Alias-esto REST API |
| OPNsense | Alias-esto + reconfigure |
| Prometheus | `/metrics` endpoint |

### 🔬 Forensiikka
- **Automaattinen PCAP** — käynnistyy Evil Twin / Deauth-hyökkäys / Honeypot -tilanteissa
- **libpcap-muoto** — Wireshark avaa suoraan, linkkityyppi 127 (802.11 + radiotap)
- **MAC-suodatus** — kaappaa vain laukaisijan liikenne

---

## Näyttökuva

```
╔════════════════════════════════════════════════════════════════════╗
║ WifiAnalyzerPro v4.0  |  Ctrl+C lopettaa                          ║
║ RSSI-skannaus [■□□] Passiivinen: 14 AP:ta | Web: localhost:8765   ║
║ Paras 2.4 GHz: CH 11 (vapaa) | Häiriöindeksi: 4.2 | Ping: 12 ms  ║
║────────────────────────────────────────────────────────────────────║
║ SSID              CH  BAND   ████████  RSSI  Q INT   Vendor  Score║
║ ►KotiVerkko        6  2.4G   ████████   -52  A  2.1  TP-Link  87.3║
║  Vierasverkko      6  2.4G   ██████░░   -65  B  5.8  Asus     71.2║
║  Naapuri_5G       36   5 G   ████░░░░   -72  C  0.0  Intel    64.8║
║ [D] ARP löytyi 8 laitetta:                                         ║
║    192.168.1.1      AA:BB:CC:11:22:33   [ARP]                      ║
║    ↳ router.lan | TP-Link Technologies                             ║
╚════════════════════════════════════════════════════════════════════╝
```

---

## Asennus

### Vaatimukset

| Komponentti | Versio |
|---|---|
| Windows | 10 build 1903+ tai Windows 11 |
| .NET SDK | 6.0+ |
| [Npcap](https://npcap.com) | 1.70+ |

> **Windows 11 24H2+**: Asetukset → Yksityisyys → Sijainti → Päälle

### 1. Kloonaa

```bash
git clone https://github.com/sinun-kayttajatunnus/WifiAnalyzerPro.git
cd WifiAnalyzerPro
```

### 2. Rakenna

```bash
dotnet build -c Release
```

### 3. Käynnistä (Admin-oikeudet)

```bash
# Suorita järjestelmänvalvojana (pakettien kaappaus vaatii Admin)
dotnet run -c Release
```

tai suorita käännetty `.exe` hiiren oikealla → "Suorita järjestelmänvalvojana".

---

## Konfiguraatio

Ohjelma luo `wifi_config.json`:n automaattisesti ensimmäisellä käynnistyskerralla. Muutokset vaikuttavat **välittömästi** — ohjelmaa ei tarvitse käynnistää uudelleen.

```jsonc
{
  // Skannaus
  "MinScanIntervalSeconds": 12,
  "StaleApMinutes": 5,

  // Hälytykset
  "RssiAlertThreshold": -80,
  "RssiAlertClearThreshold": -75,
  "AlertCooldownSeconds": 60,

  // Discord / Slack
  "DiscordWebhookUrl": "https://discord.com/api/webhooks/...",
  "SlackWebhookUrl": "https://hooks.slack.com/services/...",

  // Uhkatiedustelu (valinnainen)
  "EnableThreatIntel": false,
  "OtxApiKey": "",
  "AbuseIpDbApiKey": "",

  // PCAP-forensiikka (valinnainen)
  "EnableAutoCapture": false,
  "CaptureDirectory": "captures",
  "CaptureDurationSeconds": 60,

  // Honeypot (valinnainen)
  "HoneypotSsids": [],
  "EnableHoneypotSoftAp": false,

  // Reititin-esto (valinnainen)
  "UnifiControllerUrl": "",
  "UnifiUsername": "",
  "UnifiPassword": "",
  "PfSenseUrl": "",
  "OPNsenseUrl": ""
}
```

### OUI-tietokanta (valinnainen)

Lataa valmistajatietokanta tarkempaa laitetunnistusta varten:

```bash
# Lataa IEEE:n OUI-tietokanta
curl -o oui.csv "https://maclookup.app/downloads/csv-database/get-db"
```

### Oma blacklist

Luo `blacklist.txt` samaan hakemistoon:

```
# Yksi domain per rivi: domain [TAB vakavuus 1-3 [TAB syy]]
evil-domain.com    3    Yrityksen C2-infrastruktuuri
tracker.internal   1    Sisäinen seuranta
```

---

## Näppäinkomennot

| Näppäin | Toiminto |
|---|---|
| `S` | Pakota välitön skannaus |
| `R` | Nollaa liikennelaskurit |
| `E` | Vie raportit (JSON/CSV/HTML) |
| `C` | Generoi compliance-raportti (PCI-DSS / ISO 27001) |
| `D` | ARP-skannaus — näyttää IP, MAC, hostname, valmistaja |
| `A` | Hälytyshistorianäkymä |
| `X` | 2.4 GHz spektrinäkymä |
| `F` | SSID-suodatin |
| `Tab` | Vaihda lajittelutila |
| `↑` / `↓` | AP-valinta |
| `Enter` | AP-detaljinäkymä (PHY, roaming, PMF, ping, deauth...) |
| `Q` | WiFi-QR-koodi valitulle AP:lle |
| `Esc` | Sulje / peruuta |
| `Ctrl+C` | Lopeta |

---

## Web-dashboard

Avaa selaimessa: **http://localhost:8765**

- Reaaliaikainen SSE-päivitys (~4 s)
- Top Palvelut -piirakkakaavio (DPI)
- Verkkoaktiivisuus-aikajana (60 s)
- Deauth-aikajana
- Evil Twin, Honeypot, EAPOL, PCAP ja RouterBlock -paneelit

---

## Tietoturvaominaisuuksien aktivointi

### Uhkatiedustelu (OTX + AbuseIPDB)

1. Rekisteröidy [AlienVault OTX](https://otx.alienvault.com) (ilmainen)
2. Rekisteröidy [AbuseIPDB](https://www.abuseipdb.com) (ilmainen, 1 000 kyselyä/vrk)
3. Lisää avaimet `wifi_config.json`:iin:

```jsonc
"EnableThreatIntel": true,
"OtxApiKey": "oma-otx-avain",
"AbuseIpDbApiKey": "oma-abuseipdb-avain"
```

### Reititin-esto (Unifi)

```jsonc
"UnifiControllerUrl": "https://192.168.1.1:8443",
"UnifiUsername": "admin",
"UnifiPassword": "salasana",
"UnifiSite": "default"
```

### Automaattinen PCAP-forensiikka

```jsonc
"EnableAutoCapture": true,
"CaptureDirectory": "captures",
"CaptureDurationSeconds": 60
```

Tiedostot avautuvat suoraan Wiresharkissa.

---

## Arkkitehtuuri

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
Program.cs (konsoli, näppäimet, pääsilmukka)
```

---

## NuGet-riippuvuudet

| Paketti | Käyttötarkoitus |
|---|---|
| `ManagedNativeWifi` 2.x | Windows WLAN API |
| `SharpPcap` 6.x | Npcap-pakettikaappaus |

Kaikki muu on .NET:n vakiokirjastoa — ei ylimääräisiä riippuvuuksia.

---

## Tiedostorakenne

```
WifiAnalyzerPro/
├── AlertManager.cs          Hälytykset, cooldown, webhook
├── BehaviorProfiler.cs      Behavioral IDS, 24h baseline
├── ChannelAnalyzer.cs       Häiriöpisteytys, kaistatunnistus
├── ChannelLoadTracker.cs    BSS Load IE 11 -seuranta
├── ComplianceChecker.cs     PCI-DSS 4.0 + ISO 27001 -tarkistukset
├── CsvHelper.cs             RFC-4180 CSV-paketointi
├── DeauthTracker.cs         Deauth-myrsky + PMF-ristikäyttö
├── DeviceScanner.cs         ARP-skannaus + mDNS
├── DpiAnalyzer.cs           35 palvelua + blacklist 35+ merkintää
├── EapolTracker.cs          PMKID-keräilymalli (behavioral)
├── FrameCapabilityParser.cs HT/VHT/HE/EHT IE-parsinta
├── HiddenNodeTracker.cs     RTS/CTS + DNS/TLS SNI kaappaus
├── ILogger.cs               Lokiabstraktio (FileLogger/DebugLogger)
├── LongTermExporter.cs      Append-only CSV pitkäaikaiseen seurantaan
├── Models.cs                Kaikki datatyypit
├── OuiDatabase.cs           MAC-valmistajatietokanta
├── PassiveChannelScanner.cs Npcap 802.11-kehysparsinta
├── PcapRecorder.cs          libpcap-forensiikkanauhoitus
├── Program.cs               Pääsilmukka, konsoli, näppäimet
├── ReportExporter.cs        HTML/CSS/JS/CSV/Prometheus/Compliance
├── RouterContainment.cs     Unifi/pfSense/OPNsense REST API
├── SecurityAlertDispatcher.cs Discord/Slack/Generic webhook
├── SignalChartRenderer.cs   ASCII-kaaviot (spektri, ping, rytmi)
├── SignalStats.cs           Ring buffer + Welford + EMA
├── SpeedMonitor.cs          Ping + streaming-latausnopeus
├── ThreatIntelClient.cs     OTX + AbuseIPDB + cache + rate limiter
├── WebDashboard.cs          HTTP/SSE-palvelin, DashboardData
├── WifiAnalyzerEngine.cs    Ydinmoottori, orchestrointi
├── WifiConfig.cs            Konfiguraatio + validointi + hot-reload
├── WifiConfigWatcher.cs     FileSystemWatcher, debounce
├── WifiHoneypot.cs          Probe Request -ansa + SoftAP
└── WifiQrCode.cs            QR-koodi (Reed-Solomon, ei riippuvuuksia)
```

---

## Lailliset huomiot

- **Passiivinen kaappaus** on laillista omissa verkoissa ja verkoissa joihin sinulla on lupa.
- **Honeypot SoftAP** — käytä vain hallituissa ympäristöissä.
- **RouterContainment** — toimii vain omistamassasi infrastruktuurissa.
- Deauth-hyökkäysten *tunnistaminen* on laillista. Niiden *lähettäminen* on laitonta lähes kaikissa maissa.

---

## Lisenssi

MIT — katso [LICENSE](LICENSE)

---

*~9 500 riviä C# · 30 tiedostoa · .NET 6+ · SharpPcap · ManagedNativeWifi*
