# WifiAnalyzerPro — Täydellinen tekninen dokumentaatio

**Versio:** 4.2  
**Päivitetty:** 2026-05-27  
**Ympäristö:** Windows 10/11 · .NET 6+ · Npcap 1.70+  
**Koko:** ~10 880 riviä C# · 33 tiedostoa  

---

## Sisällysluettelo

1. [Projektin yleiskuvaus](#1-projektin-yleiskuvaus)
2. [Järjestelmävaatimukset ja asennus](#2-järjestelmävaatimukset-ja-asennus)
3. [Arkkitehtuurikatsaus](#3-arkkitehtuurikatsaus)
4. [Konfiguraatio](#4-konfiguraatio)
5. [Moduulidokumentaatio — 33 tiedostoa](#5-moduulidokumentaatio)
6. [Tietomalli](#6-tietomalli)
7. [HTTP-rajapinta ja Web-dashboard](#7-http-rajapinta-ja-web-dashboard)
8. [Tietoturvajärjestelmä](#8-tietoturvajärjestelmä)
9. [Behavioral IDS ja Honeypot](#9-behavioral-ids-ja-honeypot)
10. [Ulkoiset integraatiot](#10-ulkoiset-integraatiot)
11. [Forensiikka ja PCAP](#11-forensiikka-ja-pcap)
12. [Mesh-topologia ja roaming](#12-mesh-topologia-ja-roaming)
13. [Compliance-raportointi](#13-compliance-raportointi)
14. [Säikeistys ja säikeenturvallisuus](#14-säikeistys-ja-säikeenturvallisuus)
15. [Konsolinäkymä ja näppäinohjaus](#15-konsolinäkymä-ja-näppäinohjaus)
16. [Pisteytysalgoritmi](#16-pisteytysalgoritmi)
17. [Korjatut bugit — versiohistoria](#17-korjatut-bugit)
18. [Vianmääritys](#18-vianmääritys)

---

## 1. Projektin yleiskuvaus

WifiAnalyzerPro on Windows-komentorivisovellus joka yhdistää neljä analysointikerrosta reaaliaikaiseksi Wi-Fi-turvallisuus- ja suorituskykyanalysaattoriksi.

**Aktiivinen skannaus** — Windows WLAN API (ManagedNativeWifi) kysyy BSS-verkkoluetteloa ja käynnistää pakotetun skannauksen tarvittaessa. Adaptiivinen skannausväli minimoi häirintää.

**Passiivinen kaappaus** — SharpPcap/Npcap kuuntelee 802.11-kehyksiä promiscuous-tilassa. Parsii Beacon, Probe Request/Response, Deauth, Disassoc, RTS/CTS, Data ja EAPOL-kehykset.

**Analysointi** — Per-AP häiriöpisteet (co-channel + adjacent + BSS Load IE 11), signaalitilastot (ring buffer, Welford O(1), EMA), Evil Twin, PMF-ristikäyttö, Behavioral IDS, EAPOL-keräilytunnistus, Captive Portal, Mesh-topologia, Kanavasuositus.

**Raportointi** — Live HTML-dashboard SSE:llä, JSON-snapshot, CSV, Prometheus + alert_rules.yml, Grafana-dashboard JSON, Compliance-raportti (PCI-DSS 4.0 + ISO 27001), Discord/Slack/SMTP-webhookit, PCAP-forensiikka, Unifi/pfSense/OPNsense-integraatio.

### Ominaisuusmatriisi

| Kategoria | Ominaisuus |
|---|---|
| Skannaus | WLAN API BSS-lista · passiivinen beacon · adaptiivinen väli · hot-reload |
| Analyysi | Co-channel + adjacent penalty · BSS Load IE 11 · pisteytys A–F |
| PHY | HT/VHT/HE/EHT IE-parsinta · Wi-Fi 4–7 · MIMO · kaistanleveys · SNR |
| Roaming | 802.11k/v/r beacon-kentistä · Mesh-topologiakartta |
| Tietoturva | PMF MFPC/MFPR · Deauth-myrsky+broadcast · Evil Twin OUI+salaus |
| Behavioral IDS | 24 h baseline · 5 anomaliasääntöä · 7 vrk ring buffer |
| EAPOL | PMKID-keräilymalli (behavioral, ei kryptografinen) |
| Honeypot | Probe Request -ansa · valinnainen SoftAP (Windows Hosted Network) |
| DPI | DNS + TLS SNI · 35+ palvelua · blacklist · ThreatIntel API |
| ThreatIntel | AlienVault OTX + AbuseIPDB · L1-cache · rate limiter · whitelist |
| Captive Portal | DNS-jakauma per BSSID · automaattinen tunnistus |
| Kanavasuositus | Häiriökynnys · paras vapaa kanava · webhook |
| Hälytykset | Discord · Slack · SMTP-sähköposti · Generic webhook |
| Forensiikka | Automaattinen PCAP · libpcap · Wireshark-yhteensopiva · cleanup |
| Reititin-esto | Unifi block-sta · pfSense alias · OPNsense alias+reconfigure |
| Compliance | PCI-DSS 4.0 (6 sääntöä) + ISO 27001 (4 sääntöä) · HTML-raportti |
| Raportointi | HTML SSE · JSON · CSV · Prometheus · Grafana JSON · QR-koodi |

---

## 2. Järjestelmävaatimukset ja asennus

### Minimivaatimukset

| Komponentti | Versio | Huomio |
|---|---|---|
| Windows | 10 build 1903+ tai Windows 11 | |
| .NET | 6.0 tai uudempi | |
| Npcap | 1.70+ | https://npcap.com |
| Wi-Fi-adapteri | IEEE 802.11 | Promiscuous-tila passiiviseen kaappaukseen |

### NuGet-paketit

| Paketti | Käyttötarkoitus |
|---|---|
| ManagedNativeWifi 2.x | Windows WLAN API C#-wrapperi |
| SharpPcap 6.x | Npcap-pakettikaappaus |

### Windows 11 24H2+ sijaintioikeus

Asetukset → Yksityisyys → Sijainti → Päälle

### Tiedostorakenne

```
WiFi_AnaLyz/
├── wifi_config.json          ← konfiguraatio (luodaan automaattisesti)
├── oui.csv / oui_simple.csv  ← OUI-tietokanta (lataa IEEE:ltä)
├── blacklist.txt             ← oma DPI-blacklist (valinnainen)
├── wifi_data.json            ← viimeisin JSON-snapshot
├── wifi_data.csv             ← viimeisin CSV-raportti
├── wifi_report.html/css/js   ← live HTML-dashboard
├── alert_rules.yml           ← Prometheus-hälytyssäännöt (EnablePrometheusExport=true)
├── grafana_dashboard.json    ← Grafana-dashboard (EnablePrometheusExport=true)
├── wifi_longterm_networks.csv
├── wifi_longterm_alerts.csv
├── alerts.log
├── wifi_analyzer.log
└── captures/
    └── capture_20260527_*.pcap
```

---

## 3. Arkkitehtuurikatsaus

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Program.cs                                  │
│  Pääsilmukka · Konsoli · Näppäinohjaus · Tapahtumakytkennät         │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ Update() · GetAnalysisSnapshot()
                             ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     WifiAnalyzerEngine                               │
│  BSS-skannaus · Pisteytys · Historia · Hälytykset · Hot-reload      │
├──────┬───────┬────────┬────────┬───────┬────────┬───────────────────┤
│Alert │Channel│Signal  │Channel │OUI    │Report  │ LongTerm          │
│Mgr   │Analyze│Stats   │LoadTrk │DB     │Export  │ Exporter          │
└──────┴───────┴────────┴────────┴───────┴────────┴───────────────────┘
    │                                        │
    ▼                                        ▼
PassiveChannelScanner               WebDashboard (HTTP + SSE)
(SharpPcap/Npcap)                   MeshTopologyTracker
    │
    ├─→ DeauthTracker          (storm · PMF · broadcast · reason code)
    ├─→ FrameCapabilityParser  (HT/VHT/HE/EHT · roaming IE · PMF)
    ├─→ HiddenNodeTracker      (RTS/CTS · DNS · TLS SNI · CaptivePortal)
    │   ├─→ DpiAnalyzer        (35+ palvelua · blacklist)
    │   └─→ ThreatIntelClient  (OTX + AbuseIPDB · cache · rate limiter)
    ├─→ EapolTracker           (PMKID-keräilymalli behavioral)
    └─→ WifiHoneypot           (Probe Request -ansa · SoftAP)

BehaviorProfiler                SecurityAlertDispatcher     RouterContainment
(Behavioral IDS · 5 sääntöä)   (Discord/Slack/SMTP/Generic) (Unifi/pfSense/OPN)

PcapRecorder                    SpeedMonitor                DeviceScanner
(libpcap BinaryWriter)          (Ping + streaming DL)       (ARP + mDNS)

ComplianceChecker               SignalChartRenderer         WifiQrCode
(PCI-DSS + ISO 27001)           (ASCII-kaaviot)             (Reed-Solomon)

SignalStats        OuiDatabase       CsvHelper       ILogger
(ring+Welford+EMA) (MAC→valmistaja)  (RFC-4180)      (File/Debug)

WifiConfigWatcher  WifiConfig        Models.cs
(FileSystemWatcher)(konfiguraatio)   (kaikki datatyypit)
```

### Tietovuo per iteraatio (~4 s)

```
1. engine.Update()
   ├─ ConnectedBssidSafe ← NativeWifi (1. adapteri + break)
   ├─ NativeWifi.EnumerateBssNetworks() → AP-lista
   ├─ Päivitä SignalStats (Welford+EMA), _trafficByBssid
   ├─ RecordTraffic → BehaviorProfiler (TRAFFIC_SPIKE, DATA_EXFIL)
   ├─ Evil Twin / WeakSignal (_rssiAlertThreshold volatile)
   ├─ Stale AP:t poistetaan (_staleApTtl)
   └─ ProcessDeauthAlerts() → BlockMac() + PCAP

2. engine.GetAnalysisSnapshot()
   ├─ CalcBestChannel2G()
   ├─ ChannelLoadTracker.GetPerChannelAverage() → BSS Load per kanava
   ├─ Per AP: CalcInterference(co, adj, utilization) + Score + Grade
   ├─ ap.ChannelUtilization = _channelLoad.GetUtilization(bssid)
   └─ ap.StationCount = _channelLoad.GetStationCount(bssid)

3. engine.RunPeriodicSideEffects(snap)
   ├─ UpdateHourlyInterference()
   ├─ CheckRoamSuggestion()
   ├─ _mesh.Update(snap, ConnectedBssidSafe, _oui)
   ├─ CheckChannelRecommendation(snap)   [1/30 min]
   ├─ CheckScheduledCompliance(snap)     [1/viikko]
   ├─ PcapRecorder.CleanupDirectory()   [1/h]
   └─ BehaviorProfiler.RunChecks() + EapolTracker.DrainAlerts() [1/min]

4. engine.BuildDashboardData(snap, speed) → SSE-push
5. engine.SaveJsonReportThrottled()
```

---

## 4. Konfiguraatio

Kaikki asetukset `wifi_config.json`:ssa. `WifiConfigWatcher` havaitsee muutokset ja `ApplyConfig()` päivittää **kaikki** kentät lennossa. `_cfg` ei ole readonly → jokainen uusi arvo vaikuttaa heti.

### Skannaus

| Kenttä | Oletus | Kuvaus |
|---|---|---|
| `MinScanIntervalSeconds` | 12 | Minimitauko skannausten välillä |
| `BssStaleThresholdSeconds` | 25 | BSS-datan vanhentumisraja |
| `ScanTimeoutSeconds` | 6 | Skannauksen aikakatkaisuaika |
| `StaleApMinutes` | 5 | AP poistetaan listalta jos ei näy |

### Hälytykset

| Kenttä | Oletus | Kuvaus |
|---|---|---|
| `RssiAlertThreshold` | -80 | Heikon signaalin hälytysraja dBm |
| `RssiAlertClearThreshold` | -75 | Hystereesi-nollauspiste |
| `AlertCooldownSeconds` | 60 | Sama hälytys enintään kerran tässä ajassa |
| `AlertWebhookUrl` | "" | HTTP POST -webhook JSON-hälytyksille |

### Ulkoiset hälytykset

| Kenttä | Oletus | Kuvaus |
|---|---|---|
| `DiscordWebhookUrl` | "" | Discord Incoming Webhook |
| `SlackWebhookUrl` | "" | Slack Incoming Webhook |
| `SmtpHost` | "" | SMTP-palvelin (tyhjä = pois) |
| `SmtpPort` | 587 | SMTP-portti (587=STARTTLS, 465=SSL) |
| `SmtpUser` | "" | SMTP-käyttäjätunnus |
| `SmtpPassword` | "" | SMTP-salasana tai sovellussalasana |
| `SmtpFrom` | "wifianalyzer@localhost" | Lähettäjä |
| `SmtpTo` | "" | Vastaanottaja(t), pilkulla erotettu |
| `SmtpUseSsl` | true | SSL/TLS-yhteys |
| `SmtpAlertSeverityThreshold` | 3 | Minimivakavuus sähköpostiin |
| `BlacklistAlertSeverityThreshold` | 3 | Minimivakavuus ulkoiseen hälytykseen |
| `SecurityAlertCooldownMinutes` | 5 | Cooldown per domain |

### Uhkatiedustelu

| Kenttä | Oletus | Kuvaus |
|---|---|---|
| `EnableThreatIntel` | false | Aktivoi TI-haut |
| `OtxApiKey` | "" | AlienVault OTX API-avain |
| `AbuseIpDbApiKey` | "" | AbuseIPDB API-avain |
| `ThreatIntelCacheTtlHours` | 24 | Cache-aika tunteina |
| `ThreatIntelMaxRequestsPerHour` | 100 | Rate limit / tunti |

### Captive Portal

| Kenttä | Oletus | Kuvaus |
|---|---|---|
| `DetectCaptivePortal` | true | Tunnistus aktiivinen |
| `CaptivePortalDnsThresholdPct` | 80 | % DNS-kyselyistä samaan kohteeseen |

### Kanavasuositus

| Kenttä | Oletus | Kuvaus |
|---|---|---|
| `ChannelRecommendationThreshold` | 15.0 | Häiriöpisteraja suositukselle |
| `ChannelRecommendationWebhook` | true | Lähetä myös webhookilla |

### PCAP-forensiikka

| Kenttä | Oletus | Kuvaus |
|---|---|---|
| `EnableAutoCapture` | false | Automaattinen PCAP vakavista poikkeamista |
| `CaptureDirectory` | "." | PCAP-hakemisto |
| `CaptureDurationSeconds` | 60 | Nauhoituksen kesto |
| `CaptureMaxFileSizeBytes` | 52428800 | Maksimikoko (50 Mt) |
| `MaxConcurrentCaptures` | 3 | Samanaikaisten nauhoitusten max |
| `CaptureMaxDirectorySizeMb` | 500 | Hakemiston maksimikoko Mt |
| `CaptureRetentionDays` | 30 | PCAP-tiedostojen säilytysaika |

### Automaattinen Compliance

| Kenttä | Oletus | Kuvaus |
|---|---|---|
| `ComplianceScheduleDay` | -1 | Viikonpäivä (0=Sun…6=Sat, -1=pois) |
| `ComplianceScheduleHour` | 8 | Tunti (0–23) |

### Reititin-esto

| Kenttä | Kuvaus |
|---|---|
| `UnifiControllerUrl` | esim. `https://192.168.1.1:8443` |
| `UnifiUsername` / `UnifiPassword` / `UnifiSite` | Unifi-kirjautuminen |
| `PfSenseUrl` / `PfSenseApiKey` / `PfSenseMacAlias` | pfSense REST |
| `OPNsenseUrl` / `OPNsenseKey` / `OPNsenseSecret` / `OPNsenseMacAlias` | OPNsense |

---

## 5. Moduulidokumentaatio

### WifiAnalyzerEngine.cs (1 430 riviä)

Projektin ydinluokka. Orchestroi kaiken.

**Kriittiset kenttävalinnat:**

| Kenttä | Tyyppi | Suojaus | Syy |
|---|---|---|---|
| `_cfg` | `WifiConfig` | ei lukko | kirjoitetaan vain ApplyConfig:ssa (HotReload-säie), luetaan päälangasta; WifiConfig on käytännössä immutable arvo-olio |
| `_rssiAlertThreshold` | `volatile int` | Volatile | luetaan tiheästi skannaussilmukassa |
| `_rssiAlertClearThreshold` | `volatile int` | Volatile | hystereesi-pari |
| `_scanTimeoutSec` | `volatile int` | Volatile | voi muuttua lennossa |
| `_aps` | `Dictionary` | `_lock` | kirjoitetaan ja luetaan useasta kohdasta |
| `_processors` | `Action[]` | `_processorLock` + volatile array | pakettikäsittelijät |

**Julkinen API:**

| Metodi/Property | Kuvaus |
|---|---|
| `Update()` | Yksi skannausiteraatio |
| `GetAnalysisSnapshot()` | Pisteytettty AP-lista BSS Load + StationCount -tiedoilla |
| `BuildDashboardData(snap, speed)` | Täysi SSE-snapshot (11 turva- ja 4 tilasto-kenttää) |
| `RunPeriodicSideEffects(snap)` | Mesh · kanavasuositus · compliance · PCAP-siivous · BID |
| `ApplyConfig(newCfg)` | Hot-reload: päivittää `_cfg` + volatile-kentät + kaikki Apply()-kutsut |
| `AttachPassiveScannerEvents(scanner)` | Kytkee kaikki 8 scanner-tapahtumaa + CaptivePortal |
| `StartHoneypotSoftAp(ssid)` | Käynnistää netsh-haamutukiaseman |
| `ExportComplianceReport(report)` | Delegoi ReportExporter:lle |
| `ThreatIntelStatus` | Luettava property TI-moottorin tilasta |
| `GetMeshTracker()` | MeshTopologyTracker-viite dashboardille |

**Tapahtumat:**

| Tapahtuma | Parametrit | Kuvaus |
|---|---|---|
| `DpiEventOccurred` | `TrafficObservation` | Uusi DNS/SNI-havainto |
| `HoneypotEventOccurred` | `HoneypotEvent` | Probe tai deauth decoy-verkkoon |
| `AnomalyDetected` | `AnomalyAlert` | Behavioral IDS -poikkeama |

---

### AlertManager.cs (223 riviä)

Cooldown · hystereesi · lokitus · webhook.

**Toiminta:** `Add(type, bssid, message)` tarkistaa suppression-listan, cooldown-ajan (`volatile int _cooldownSeconds`), lisää `AlertEntry`-olion listaan (`lock(_alertLock)`), kirjoittaa `alerts.log`:iin (`lock(_logFileLock)`) ja ampuu webhook-POST:n taustasäikeessä.

**Hystereesi:** `SetWeakSignal(bssid, true/false)` — signaali hälyttää vain kerran kunnes se palautuu `RssiAlertClearThreshold`:n yli.

**GetAll():** Palauttaa `new List<AlertEntry>(_alerts)` — kopion, ei elävää viitettä. Lukittu `_alertLock`:lla.

**Hälytyslajit:** `NewAP`, `WeakSignal`, `EvilTwin`, `Roaming`, `RoamSuggestion`, `DeauthStorm`, `DeauthBroadcast`, `EapolAttack`, `Anomaly_*`, `Honeypot`, `Blacklist`, `ThreatIntel`, `CaptivePortal`, `ChannelRecommendation`

---

### BehaviorProfiler.cs (372 riviä)

Behavioral IDS: per-laite 24 h baseline + anomaliatunnistus.

**State-tietorakenne:**

```
HourlyBytes[168]      — 7 vrk × 24 h liikennehistoria (long)
HourlyObs[168]        — havainnot per slot (int)
HourlySlotEpoch[168]  — syklinumero per slot (long) ← v4.0 ring buffer -korjaus
SlotResetLock         — object, suojelee nollausta
HourActivity[24]      — aktiivisuus per tunti
RecentArps            — liukuva 60 s ARP-jono
RecentDns             — liukuva 30 min DNS-jono
KnownHosts            — historian tunnetut domainit
```

**Ring buffer -korjaus (v4.0):** `EpochCycle()` palauttaa 7 vrk -syklinumeron (`(DateTime.Now - epoch).TotalHours / 168`). `RecordTraffic` tarkistaa `lock(s.SlotResetLock)`:in sisällä — jos `HourlySlotEpoch[h] != cycle` → nollaa `HourlyBytes[h]` ja `HourlyObs[h]` ennen `Interlocked.Add`:ia.

**Anomaliasäännöt:**

| Sääntö | Logiikka | Pisteet |
|---|---|---|
| `TRAFFIC_SPIKE` | Nykyhetki > 5× saman tunnin 7 vrk baseline | 40–100 |
| `NIGHT_ACTIVITY` | Aktiivinen 00–05, ei koskaan aiemmin | 55 |
| `ARP_SWEEP` | >20 ARP-kyselyä / min | 60–100 |
| `DNS_EXPLOSION` | >60 % DNS tuntemattomiin | 40–90 |
| `DATA_EXFIL` | >10 Mt siirretty yöllä 00–05 | 70–100 |

Pisteet: ≥40 epäilyttävä · ≥70 todennäköinen · ≥90 kriittinen. Cooldown 10 min per laite.

---

### ChannelAnalyzer.cs (189 riviä)

Häiriöpisteet, kaistatunnistus, kanavakuorma.

**CalcInterference:**
```
penalty = co × CoChannelWeight + adj × AdjacentWeight
          × (1 + min(1.0, utilization/100))   ← BSS Load -kerroin
```

**PhyToBand(phy, channel, frequencyMhz):**
1. Frekvenssi MHz → yksikäsitteinen (5925–7125 = 6 GHz)
2. Kanava 36–177 → 5 GHz aina
3. Wi-Fi 6E/7 PHY + kanava 15–35 tai >177 → 6 GHz
4. Kanava 1–14 → 2.4 GHz

---

### ChannelLoadTracker.cs (104 riviä)

Säikeenturvallinen BSS Load IE 11 -seuranta.

| Metodi | Kuvaus |
|---|---|
| `Update(bssid, ch, util, stations)` | Kirjaa BSS Load -datan BeaconReceived-tapahtumasta |
| `GetUtilization(bssid)` | Palauttaa BSSID-kohtaisen kuorman (null = ei dataa) |
| `GetStationCount(bssid)` | Palauttaa yhdistettyjen asemien määrän (null = ei dataa) |
| `GetPerChannelAverage()` | Kanavakohtainen keskiarvo CalcInterference:lle |
| `Prune(maxAge)` | Poistaa vanhentuneet AP:t |

Sisäinen rakenne: `ConcurrentDictionary<bssid, Entry>` jossa `Entry` on struct (Channel, Utilization 0–100, StationCount -1=tuntematon, UpdatedUtc).

---

### ComplianceChecker.cs (275 riviä)

PCI-DSS 4.0 + ISO 27001:2022 -vaatimustenmukaisuustarkistus.

**10 sääntöä:**

| ID | Standardi | Tarkistus | FAIL-ehto |
|---|---|---|---|
| PCI-4.2.1 | PCI-DSS 4.0 | Ei WEP/WPA1/Open | Security == "WEP" tai "WPA" tai "Open" |
| PCI-4.2.1b | PCI-DSS 4.0 | Avoimet verkot | Security == "Open" |
| PCI-2.2.7 | PCI-DSS 4.0 | PMF pakotettu | PmfRequired == false WPA2+:lla |
| PCI-11.2.2 | PCI-DSS 4.0 | Evil Twin -hälytykset | EvilTwin-hälytyksiä 24 h:ssa |
| PCI-11.2.1 | PCI-DSS 4.0 | Deauth-hyökkäykset | Deauth/Broadcast-hälytyksiä 24 h:ssa |
| PCI-8.3.6 | PCI-DSS 4.0 | WPA3 käyttöaste | < 80 % AP:ista WPA3 |
| ISO-A.8.20-1 | ISO 27001 | Kaikilla WPA2+ | Security < WPA2 |
| ISO-A.8.20-2 | ISO 27001 | BSS Load < 80 % | ChannelUtilization ≥ 80 |
| ISO-A.8.20-3 | ISO 27001 | Yhdistetyn signaali | RSSI < -75 dBm |
| ISO-A.8.20-4 | ISO 27001 | EAPOL-tunnistus | EapolSummary.Suspicious > 0 |

**Pisteytys:** Pass=10 p · Info=8 p · Warning=5 p · Fail=0 p → Grade A(≥90)/B/C/D/F(<60)

---

### CsvHelper.cs (21 riviä)

RFC-4180-yhteensopiva CSV-paketointi.

- `Escape(s)` — lisää lainausmerkit jos sisältää `,`, `"`, `\n` tai `\r`; kaksinkertaistaa sisäiset lainausmerkit
- `Row(params string[])` — yhdistää jo pakotetut kentät pilkulla (ei pakota itse uudelleen)

---

### DeauthTracker.cs (240 riviä)

Liukuvan 10 s ikkunan Deauth/Disassoc-myrskytunnistus.

**PMF-ristikäyttö:**

| Ehto | Johtopäätös |
|---|---|
| MFPR=1 + salaamaton Deauth | **VARMENNETTU HYÖKKÄYS** (severity 3) |
| MFPC=1 + salaamaton Deauth | **TODENNÄKÖINEN HYÖKKÄYS** (severity 2) |

**Reason Code -sormenjälki:**

| Koodi | Työkalu |
|---|---|
| 1 | aireplay-ng / mdk oletusarvo |
| 7 | aireplay-ng -0 / wifijammer |
| 4 | mdk3/mdk4 |

**Sliding window:** `while (q.Peek().Time < cutoff) q.Dequeue()` — siivoaa vanhat ennen laskentaa.

**DrainAlerts():** Tyhjentää jonot, palauttaa `(Bssid, Message, IsBroadcast)` -tuplet PMF- ja reason code -tageilla.

---

### DeviceScanner.cs (164 riviä)

ARP-skannaus + mDNS-kuuntelu.

**ARP:** `Parallel.For(1, 255, MaxDegreeOfParallelism=32)` → ICMP ping → ARP-välimuistista MAC → DNS-nimiresoluutio → OUI-valmistajahaku.

**ARP-näyttö (v4.0+):** 2 riviä per laite:
```
    192.168.1.1      AA:BB:CC:11:22:33   [ARP]
    ↳ router.lan | TP-Link Technologies
```

**mDNS:** UDP multicast 224.0.0.251:5353, parsii Label-enkoodatun nimen.

---

### DpiAnalyzer.cs (201 riviä)

Palvelutunnistus 35+ palvelulle + blacklist-tarkistus.

**Palvelukategoriat:** Suoratoisto (Netflix, YouTube, Spotify, Twitch, Disney+, HBO Max, Prime Video) · Pilvipalvelut (Apple, Google, Microsoft, AWS, Azure, Cloudflare) · Sosiaalinen media (Facebook, Instagram, Twitter, TikTok, LinkedIn, Reddit) · Viestintä (Discord, Slack, WhatsApp, Telegram, Zoom, Teams) · Pelit (Steam, Epic, PlayStation, Xbox) · CDN (Cloudflare, Akamai, Fastly)

**Blacklist-kategoriat (sisäänrakennettu + blacklist.txt):**

| Kategoria | Esimerkkejä | Vakavuus |
|---|---|---|
| C2 / Malware | Trickbot, Emotet, CobaltStrike | 3 |
| Cryptomining | XMRig, Nanopool, F2Pool | 3 |
| IoT-botnet | Mirai-variantit | 3 |
| DNS-tunneling | dnscat, iodine, dns2tcp | 3 |
| Pentest OOB | Burp Collaborator, interactsh | 2 |
| Tracking | DoubleClick | 1 |

**blacklist.txt formaatti:** `domain [TAB vakavuus 1-3 [TAB syy]]`

---

### EapolTracker.cs (160 riviä)

PMKID-keräilyhyökkäyksen behavioral-tunnistus.

**Periaate:** Sama MAC kättelee >3 eri AP:ta 60 sekunnissa. Normaali laite käyttää vain yhtä AP:ta kerrallaan — hyökkääjän työkalu (hcxdumptool) käy kaikki näkyvät AP:t läpi.

**Tärkeä rajoitus:** Ei parsita EAPOL-Key-kehyksen kryptografisia kenttiä. Ainoastaan EtherType 0x888E havaitaan ja kättelyaloitusten (clientMac, bssidMac) parit lasketaan.

**`GetSummary()`** palauttaa `List<EapolSummaryEntry>`: `ClientMac`, `DistinctAps`, `Suspicious` (true jos >3 AP:ta).

---

### FrameCapabilityParser.cs (363 riviä)

IEEE 802.11 IE-kyvykkyysparsinta beacon-kehyksistä.

**Parsitut IE-kentät:**

| ID | Nimi | Parsittu tieto |
|---|---|---|
| 0 | SSID | Verkon nimi |
| 3 | DS Parameter Set | Kanavanumero |
| 11 | BSS Load | StationCount + ChannelUtilization |
| 45 | HT Capabilities | Wi-Fi 4, MCS, 40 MHz |
| 48 | RSN Information | WPA2/WPA3 AKM + MFPC/MFPR |
| 55/54 | FT / MD Element | 802.11r |
| 70 | RRM Capabilities | 802.11k |
| 127 | Extended Capabilities | 802.11v (byte 3 bit 3) |
| 191 | VHT Capabilities | Wi-Fi 5, 80/160 MHz |
| 255 ext 35 | HE Capabilities | Wi-Fi 6/6E |
| 255 ext 108 | EHT Capabilities | Wi-Fi 7 |
| 221 | Vendor Specific | WPA1, WPS |

**Maksiminopeus-estimaatit (per virta, 800 ns GI):**

| PHY | 20 MHz | 40 MHz | 80 MHz | 160 MHz |
|---|---|---|---|---|
| HT (Wi-Fi 4) | 72 Mbps | 150 Mbps | — | — |
| VHT (Wi-Fi 5) | — | — | 433 Mbps | 867 Mbps |
| HE (Wi-Fi 6) | 143 Mbps | 287 Mbps | 600 Mbps | 1201 Mbps |
| EHT (Wi-Fi 7) | — | — | 720 Mbps | 1441 Mbps |

---

### HiddenNodeTracker.cs (394 riviä)

RTS/CTS-analyysi + DPI + Captive Portal -tunnistus.

**Hidden Node -indikaattori:**
```
CtsResponsePct = CtsCount / RtsCount × 100 %
HiddenNodeSuspected = MissedCts > 10 AND CtsResponsePct < 70 %
```

**DNS-parsinta:** UDP/53, QR bit=0, QDCOUNT≥1, Label-enkoodaus.

**TLS SNI -parsinta:** TCP/443, ContentType 22 (Handshake), HandshakeType 1 (ClientHello), extension server_name (type 0).

**Captive Portal -tunnistus:**
- Seuraa per-BSSID DNS-kyselyiden jakaumaa (`_dnsIpsByBssid`)
- Tarkistaa kun `_dnsTotalByBssid[bssid] >= 10` (min otoskoko)
- Jos dominant-kohde ≥ `CaptivePortalThresholdPct` % (oletus 80 %) → `CaptivePortalDetected?.Invoke(bssid, dominantTarget)`
- Hälyttää vain kerran per BSSID (`_captivePortals.TryAdd`)

**Tapahtumat:** `ObservationRecorded(TrafficObservation)` · `CaptivePortalDetected(bssid, dominantTarget)`

---

### ILogger.cs (46 riviä)

Lokiabstraktio.

| Luokka | Kuvaus |
|---|---|
| `IWifiLogger` | Rajapinta: `Log(string message)` |
| `DebugLogger` | `System.Diagnostics.Debug.WriteLine` (thread-safe) |
| `FileLogger` | Append-only `File.AppendAllText` aikaleimalla, `lock(_lock)` |
| `AppLogger` | Staattinen fasadi, konfiguroidaan kerran `Configure(IWifiLogger)`:lla |

`FileLogger.Log()` sisältää `catch { }` — IO-virhe ei kaada pääohjelmaa. Halutessasi korvaa `catch (Exception ex) { Debug.WriteLine(ex.Message); }`.

---

### LongTermExporter.cs (135 riviä)

Append-only CSV pitkäaikaiseen seurantaan.

| Metodi | Kuvaus |
|---|---|
| `SaveSnapshot(aps, alerts)` | Lisää rivit `wifi_longterm_networks.csv` ja `wifi_longterm_alerts.csv` |
| `PurgeOldRows(maxAge)` | Siivoa vanhat rivit streaming-kopiointina (ei OOM-riskiä) |

`PurgeOldRows` kirjoittaa väliaikaistiedostoon rivit joita ei poisteta, sitten `File.Replace` — atomiinen vaihto.

---

### MeshTopologyTracker.cs (299 riviä)

Mesh-verkkojen topologiaseuranta ja roaming-tunnistus.

**Tietorakenteet:**
- `_groups: ConcurrentDictionary<ssid, MeshGroup>` — ryhmät SSID:n mukaan
- `_history: ConcurrentQueue<RoamingEvent>` — max 200 roaming-tapahtumaa
- `_lastConnectedBssid/Ssid/At` — edellinen yhdistys roaming-tunnistukseen

**Roaming-tunnistus:** `ConnectedBssidSafe` vaihtuu SSID:n sisällä → `RoamingEvent` + `UpdateLink()`.

**O(n) optimointi (v4.2):** Roaming-laskurit lasketaan ennen node-rakentamista yhteen Dictionary:hin — ei `Count(r => r.ToBssid == bssid)` O(n²) kutsua joka AP:lle.

**BuildSvg(grp, width, height):** Palauttaa SVG-merkkijonon:
- AP-solmut ympyrän kehälle (trigonometria)
- Väri: vihreä=yhdistetty, sininen=hyvä signaali, oranssi=heikko, punainen=erittäin heikko
- Nuolet roaming-suuntaan, paksuus = roaming-kerrat
- `↷N` merkki jos roaming-kerrat > 0

**MeshGroup:** `Ssid`, `Nodes: List<MeshNode>`, `Links: List<MeshLink>`, `IsMesh` (≥2 AP).

---

### Models.cs (288 riviä)

Kaikki datatyypit yhdessä tiedostossa.

**Tärkeimmät luokat:**

| Luokka | Tärkeimmät kentät |
|---|---|
| `AnalyzedAccessPoint` | Bssid, Ssid, Rssi, Band, Channel, Security, Grade, Score, ChannelUtilization, StationCount, PhyGeneration, Supports80211k/v/r, PmfCapable/Required, IsConnected |
| `AlertEntry` | Time, Type, Bssid, Message |
| `SpeedSample` | Time, PingMs, ThroughputKBs, Gateway |
| `TrafficObservation` | Name, Kind, ServiceName, IsBlacklisted, BlacklistSeverity, SourceMac, Bssid |
| `HiddenNodeStat` | Bssid, RtsCount, CtsCount, MissedCts, CtsResponsePct, HiddenNodeSuspected |
| `BeaconInfo` | IntervalTu, IntervalMs, LoadTag |
| `SignalPoint` | Time, Rssi |
| `HourlyInterference` | Hour, AvgPenalty, MaxPenalty |
| `PassiveBeaconInfo` | Bssid, Ssid, Channel, Rssi, Capabilities |
| `DeauthEvent` | SenderMac, TargetMac, Bssid, ReasonCode, IsBroadcast, Time |

---

### OuiDatabase.cs (168 riviä)

MAC-valmistajatietokanta.

**Double-checked locking:**
```csharp
if (_loaded) return;              // nopea tarkistus
lock (_loadLock) {
    if (_loaded) return;          // lukon sisällä uudelleen
    // ... lataus ...
}
```

`_loaded` on `private volatile bool` — pakollinen double-checked lockingille 32-bittisillä alustoilla.

**Tuetut formaatit:**
- `AABBCC,Vendor Name` (yksinkertainen)
- `Registry,Assignment,Organization,Address` (IEEE-virallinen)

**GetOrAdd-pattern:** `_vendorCache.GetOrAdd(prefix, _ => LoadIfNeeded(); _ouiVendors.TryGetValue(...))` — kutsuu `LoadIfNeeded` laiskasti.

---

### PassiveChannelScanner.cs (407 riviä)

SharpPcap/Npcap-pohjainen kehyskaappaus.

**8 tapahtumaa (kaikki `?.Invoke` atomiisia):**

| Tapahtuma | Parametrit | Triggeröityy |
|---|---|---|
| `BeaconReceived` | `PassiveBeaconInfo` | Beacon (subtype 8) tai Probe Response (5) |
| `DeauthReceived` | `DeauthEvent` | Deauth (12) tai Disassoc (10) |
| `ProbeRequestDetected` | `(srcMac, ssid, data, off)` | Probe Request (4), kohdennettu |
| `RtsReceived` | `int channel` | RTS Control (27) |
| `CtsReceived` | `int channel` | CTS Control (28) |
| `DnsQueryDetected` | `(hostname, srcMac, bssid)` | DNS A/AAAA avoimesta verkosta |
| `TlsSniDetected` | `(sni, srcMac, bssid)` | TLS ClientHello avoimesta verkosta |
| `EapolFrameDetected` | `(clientMac, bssidMac)` | EtherType 0x888E |

**EAPOL ennen Protected-checkiä:** 0x888E tarkistetaan ennen `isProtected`-lipun tarkistusta — 4-way handshake on aina salaamatonta ennen avainten neuvottelua.

**Rajoitukset:** RTS/CTS-kanavatieto = 0 (tuntematon, radiotapista lukeminen ei toteutettu). 6GHz kanavat 1/5/9/13 erottamattomissa 2.4GHz:stä ilman frekvenssitietoa.

---

### PcapRecorder.cs (271 riviä)

Forensinen PCAP-nauhoitus.

**libpcap global header:**

| Kenttä | Arvo |
|---|---|
| Magic | `0xA1B2C3D4` (little-endian, µs) |
| Versio | 2.4 |
| Snaplen | 65535 |
| Network | 127 (IEEE 802.11 + radiotap) |

**Start(directory, reason, mac):** Luo per-recording `CancellationTokenSource` (ei luokkatason) — `Dispose()` on oikein tyhjä.

**CleanupDirectory(dir, retentionDays, maxSizeMb):**
1. Poistaa tiedostot > `retentionDays` vanhoja
2. Poistaa vanhimmat kunnes koko < `maxSizeMb` Mt
3. Kutsutaan kerran tunnissa `RunPeriodicSideEffects`:sta

---

### Program.cs (703 riviä)

Pääsilmukka, konsoli, näppäinohjaus.

**Käynnistyssekvenssi:**
1. Lataa `WifiConfig`, alusta `AppLogger`
2. Luo engine + kaikki komponentit
3. Kytkee tapahtumat: `DpiEventOccurred`, `HoneypotEventOccurred`, `AnomalyDetected`
4. Tarkistaa `EnableHoneypotSoftAp` → `StartHoneypotSoftAp()`
5. `AttachPassiveScannerEvents` + `AttachPacketProcessor`
6. Käynnistää `webDashboard`, `speedMonitor`, `deviceScanner`
7. Pääsilmukka: `Update()` → `GetAnalysisSnapshot()` → `RunPeriodicSideEffects()` → `BuildDashboardData()` → konsolipiirto

---

### ReportExporter.cs (1 496 riviä)

Kaikki raporttimuodot yhdessä luokassa.

| Metodi | Tuottaa | Kuvaus |
|---|---|---|
| `ExportAll(aps, alerts, ...)` | JSON + CSV + HTML + opt. Prometheus + Grafana | Täysi vientipaketti |
| `GetPrometheusMetrics(aps, alerts, speed)` | Prometheus text-format | `/metrics` endpoint |
| `ExportComplianceReport(report, dir)` | HTML-tiedosto | PCI-DSS + ISO 27001 |
| `ExportPrometheusAlertRules(dir)` | `alert_rules.yml` | 7 valmista Prometheus-sääntöä |
| `ExportGrafanaDashboard(dir)` | `grafana_dashboard.json` | Grafana 10+ dashboard |

**Prometheus-metriikat:** `wifi_rssi_dbm`, `wifi_interference_penalty`, `wifi_channel_utilization_pct`, `wifi_ping_ms`, `wifi_throughput_kbps`, `wifi_deauth_count_total`, `wifi_evil_twin_detected`, `wifi_security_open`, `wifi_threat_intel_hits_total`

**Prometheus alert_rules.yml (7 sääntöä):** `WifiDeauthStorm` · `WifiHighInterference` · `WifiWeakSignal` · `WifiOpenNetwork` · `WifiHighChannelLoad` · `WifiEvilTwin` · `WifiThreatIntelHit`

---

### RouterContainment.cs (267 riviä)

REST API -integraatio omaan verkkoinfraan.

| Reititin | API | Autentikointi |
|---|---|---|
| Unifi | `POST /api/login` + `POST /api/s/{site}/cmd/stamgr` | Cookie |
| pfSense | `POST /api/v1/firewall/alias/host` | API-avain tai Basic |
| OPNsense | `POST /api/firewall/alias/addHost/{alias}/{mac}` + reconfigure | API-avain+secret |

Self-signed-sertifikaatit hyväksytään. Cooldown 60 min per MAC. `Apply(cfg)` päivittää hot-reloadin yhteydessä.

---

### SecurityAlertDispatcher.cs (284 riviä)

Discord · Slack · SMTP · Generic HTTP webhook.

**Kanavavalinta:** Kaikki konfiguroidut kanavat saavat jokaisen hälytyksen. SMTP:llä erillinen `SmtpAlertSeverityThreshold`.

**Cooldown:** `ConcurrentDictionary<"tyyppi:domain", DateTime>` — sama kohde hälyttää enintään kerran `SecurityAlertCooldownMinutes` aikavälillä.

**Discord embed:** väri punainen/oranssi/keltainen, `username = "WifiAnalyzerPro"`, kentät: Kohde + Selitys + Vakavuus/3 + Aikaleima.

**Slack Block Kit:** attachment värikoodauksella, mrkdwn-muotoilu.

**SMTP:** HTML-muotoinen sähköposti, `using var SmtpClient` (Dispose), `System.Net.NetworkCredential`.

**Split-fix:** `Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)` — yhteensopiva kaikkien .NET-versioiden kanssa.

---

### SignalChartRenderer.cs (228 riviä)

Kaikki ASCII-kaaviot staattisessa luokassa.

| Metodi | Kuvaus |
|---|---|
| `GetSignalChart(stats, bssid, beacon, width)` | RSSI-waveform, 6 riviä korkea, 8-tason lohkomerkit |
| `GetDailyRhythmChart(stats, barWidth)` | Tuntikohtainen häiriöpylväsdiagrammi |
| `GetChannelChart(aps, barWidth)` | Kanavakuorma 2.4/5/6 GHz |
| `GetSpectrumChart(aps, width)` | Spektrianalyysi: 2.4G taajuusvyöhyke + 5G/6G kartta |
| `GetPingChart(samples, width)` | Ping-historia, jokainen piste omalla rivillä |

**Band24Spectrum:** Kanavat 1–13, jokainen AP omalla rivillä (SSID-rivi + spektriviiva). 40 MHz leveillä verkoilla `span=4`, 20 MHz:llä `span=2`.

**BandNSpectrum:** 5G/6G AP:t pylväinä, RSSI-täyttöprosentti = (RSSI+100)/70.

---

### SignalStats.cs (99 riviä)

Ring buffer (120 pistettä) + Welford online-algoritmi + EMA-pari.

| Metriikka | Algoritmi | Suoritusaika |
|---|---|---|
| Jitter | `√(M2/n)` — populaatiovarianssi | O(1) per piste |
| Trendi | `EMA(α=0.25) − EMA(α=0.04)` | O(1) per piste |
| Historia | Ring buffer `_head` kiertyy | O(1) per piste |

`IsDirty`-lippu estää `BuildHistorySnapshot()`-kutsun turhat toistot. `SeedFromHistory` lataa historia JSON:sta käynnistyksen yhteydessä.

---

### SpeedMonitor.cs (140 riviä)

Ping-mittaus + HTTP-latausnopeustesti.

**Streaming-lataus:** `HttpCompletionOption.ResponseHeadersRead` + `ReadAsync` 8 KB-paloissa. Stopwatch alkaa vastauksen alusta → tarkempi throughput-estimaatti hitaalla yhteydellä.

**O(n) dequeue-korjaus:** `int excess = _samples.Count - MaxSamples; for (...) TryDequeue()` — yksittäinen Count-kutsu per sample (ei `while`-looppia joka kutsuisi Count:ia joka kierroksella).

---

### ThreatIntelClient.cs (336 riviä)

Ulkoinen uhkatiedustelu AlienVault OTX + AbuseIPDB.

**Kolmikerroksinen arkkitehtuuri:**

```
L1 Muisticache  — ConcurrentDictionary<domain, CacheEntry> TTL 24 h
In-flight dedup — ConcurrentDictionary<domain, byte> estää duplikaattikutsut
Rate limiter    — SemaphoreSlim(1,1) + tuntikohtainen laskuri
```

**Whitelist (40+ domainia):** Google, Apple, Microsoft, AWS, Azure, Cloudflare, Akamai, Netflix, YouTube, Discord, Slack, Spotify, Dropbox, GitHub jne. — ei koskaan katsota API:sta.

**GetRootDomain:** `"sub.evil.com"` → `"evil.com"` — säästää API-kutsut ja cache-tilaa.

**OTX API:** `GET /api/v1/indicators/domain/{domain}/general` — `pulse_info.count ≥ 2` → Malicious.

**AbuseIPDB API:** `GET /api/v2/check?ipAddress={ip}` — score ≥ 80 → Malicious, ≥ 50 → Suspicious. Vain IP-osoitteille (ei domain-resoluutiota yksityisyyssyistä).

**Callback-integraatio:** Jos TI palauttaa uhkan → `_alerts.Add("ThreatIntel", ...)` + `_alertDispatcher.SendAsync(...)` + `_routerContainment.BlockMac(...)` (Malicious) + tallennetaan `_tiHits`-jonoon dashboardille.

---

### WebDashboard.cs (494 riviä)

`System.Net.HttpListener` — ei NuGet-riippuvuuksia.

**Endpointit:**

| Polku | Kuvaus |
|---|---|
| `GET /` | `wifi_report.html` |
| `GET /api/data` | Täysi `DashboardData` JSON |
| `GET /api/events` | Server-Sent Events -stream |
| `GET /metrics` | Prometheus (EnablePrometheusExport=true) |

**SSE-karaisu:**

| Parametri | Arvo | Kuvaus |
|---|---|---|
| `WriteTimeoutMs` | 3000 | Hidas asiakas poistetaan |
| `MaxSseClients` | 10 | Yli menevät saavat HTTP 503 |
| `_pushInFlight` | Interlocked | Vain yksi täysi push kerrallaan |
| `DpiRateLimitMs` | 400 | DPI-pushien max tahti |
| `DpiQueueMax` | 50 | DPI-jonon max koko |

**DashboardData-kentät (15 kpl):**
`Timestamp · Networks · AlertCount · Speed · BestChannel · ScanStatus · IsScanRunning · RecentAlerts · RecentDeauths · ActiveAttackLevel · AttackSummary · EvilTwinAlerts · EvilTwinBssids · HiddenNodeStats · TrafficLog · PcapActiveCount · PcapRecentFiles · RouterBlockLog · EapolSummary · HoneypotEvents · ThreatIntelStatus · ThreatIntelHits · MeshGroups · RecentRoaming · CaptivePortals`

---

### WifiAnalyzerEngine.cs — CheckChannelRecommendation

**Logiikka:**
1. Tarkista onko yhdistetyn AP:n `InterferencePenalty ≥ ChannelRecommendationThreshold`
2. Valitse kandidaattikaistanleveydet (2.4G: 1/6/11, 5G: UNII-kanavat)
3. Laske AP:iden määrä per kanava
4. Valitse kanava pienimmällä AP-määrällä
5. Lähettää loki + hälytys + valinnainen webhook (max 1 krt / 30 min)

---

### WifiConfig.cs (229 riviä)

**WifiConfigLoader.Validate(cfg)** tarkistaa 12 sääntöä: RSSI-hystereesi, negatiiviset arvot, URLien muoto, hakemistojen olemassaolo jne.

**WifiConfigWatcher** (93 riviä): `FileSystemWatcher` debounce-toteutus. Kaksi `long`-Interlocked-tarkistusta (debounce 500 ms) — 64-bittinen `DateTime.Ticks` ei ole atomiinen 32-bittisillä alustoilla.

---

### WifiHoneypot.cs (300 riviä)

Kaksikerroksinen Wi-Fi-ansa.

**Taso 1 — Passiivinen:** Probe Request (subtype 4) → `ParseSsidIE()` → `_decoySet.Contains(probedSsid)` → `HoneypotEvent`. Cooldown 5 min per MAC (`_seenMacs`).

**Oletukset decoy-SSID:t:** `Free_Public_WiFi`, `NETGEAR`, `Linksys`, `Guest`, `Admin_Network`, `TestAP`, `xfinitywifi`, `attwifi`

**Taso 2 — Aktiivinen SoftAP:**
```
netsh wlan set hostednetwork mode=allow ssid="..." key=""
netsh wlan start hostednetwork
```
BSSID luetaan `netsh wlan show hostednetwork` -tuloksesta. `lock(_softApLock)` suojelee tilaa.

**Dispose():** Kutsuu `StopSoftAp()` jos `_softApRunning`.

**`EventDetected`-tapahtuma** laukaistaan `EmitEvent`:stä → engine välittää `HoneypotEventOccurred`:lle → Program.cs lokittaa.

---

### WifiQrCode.cs (461 riviä)

QR-koodgeneraattori ilman ulkoisia riippuvuuksia.

**URI-muoto:** `WIFI:T:WPA2;S:KotiVerkko;P:salasana123;;`

**Prosessi:**
1. UTF-8 tavutus
2. Versioselektio (2–10) kapasiteetin mukaan
3. Byte-moodi enkoodaus
4. Reed-Solomon GF(2⁸) virheen korjaustiedot
5. Codeword interleaving
6. Matrix: finder patterns, timing, alignment, format info
7. Kaikki 8 maskia evaluoitu 4 penalty-säännöllä
8. ASCII-renderointi (▄/▀ puoliblokkeilla)

---

## 6. Tietomalli

### AnalyzedAccessPoint — tärkeimmät kentät

| Kenttä | Tyyppi | Kuvaus |
|---|---|---|
| `Bssid`, `Ssid` | string | Tunnisteet |
| `Rssi` | int | dBm |
| `Band` | string | "2.4 GHz" / "5 GHz" / "6 GHz" |
| `Channel` | int | Kanavanumero |
| `Security` | string | Open/WEP/WPA/WPA2/WPA2-Ent/WPA2/3/WPA3 |
| `Grade` | string | A/B/C/D/F |
| `Score` | double | Lajittelupisteet |
| `InterferencePenalty` | double | Häiriöpisteet |
| `ChannelUtilization` | int? | BSS Load 0–100 % (null = ei IE 11) |
| `StationCount` | int? | Yhdistettyjä asemia (null = ei IE 11) |
| `PhyGeneration` | string | "Wi-Fi 4" – "Wi-Fi 7" |
| `MaxDataRateMbps` | int? | Teoreettinen max |
| `SpatialStreams` | int? | MIMO-virrat |
| `SnrDb` | int? | Signal-to-Noise Ratio |
| `Supports80211k/v/r` | bool | Roaming-standardit |
| `PmfCapable` / `PmfRequired` | bool | Management Frame Protection |
| `IsConnected` | bool | Yhdistetty tähän AP:iin |
| `TrafficBytes` | long | Liikennebytejä tässä istunnossa |

---

## 7. HTTP-rajapinta ja Web-dashboard

### Dashboard-ominaisuudet

- **Hyökkäysbanneri** — vilkkuu `ActiveAttackLevel` 3:ssa
- **Top Palvelut -piirakka** — Chart.js doughnut, päivittyy per DPI-SSE
- **Verkkoaktiivisuus-aikajana** — 60 s, pinottu per palvelu
- **Deauth-aikajana** — oranssi=Deauth, punainen=Broadcast
- **Evil Twin -korostus** — AP-rivin punainen reuna
- **Blacklist-rivi** — tummanpunainen tausta DPI-paneelissa
- **PCAP-paneeli** — vilkkuva punainen piste kun nauhoittaa
- **Reititinblokkaukset** — flash-animaatio uusille riveille
- **EAPOL-paneeli** — punaisella epäilyttävät laitteet
- **Honeypot-paneeli** — violetti vasen reuna
- **TI-paneeli** — Malicious punaisella, Suspicious oranssilla
- **Mesh-topologia** — SVG-kaavio roaming-nuolilla

### Prometheus-integraatio

Ota käyttöön: `"EnablePrometheusExport": true` → generoi automaattisesti:
- `alert_rules.yml` — kopioi Prometheuksen `rules/`-hakemistoon
- `grafana_dashboard.json` — tuo Grafanaan: Dashboards → Import → Upload JSON

---

## 8. Tietoturvajärjestelmä

### Evil Twin -tunnistus

```
Uusi BSSID samalla SSID:llä:
  1. OUI-vertailu: eri valmistaja → taso 1 (epäilty)
  2. IsSecurityDowngrade(): heikompi salaus → taso 2 (todennäköinen)
  3. MFPR=1 + salaamaton Deauth → taso 3 (varmennettu)
  Suodatin: IsMacRandomized() → ohitetaan locally administered -MAC:t
```

### Captive Portal -tunnistus

```
DnsQueryDetected(hostname, srcMac, bssid)
  → HiddenNodeTracker.RecordDnsHostname()
     → TrackCaptivePortalDns(bssid, hostname)
        → _dnsIpsByBssid[bssid][hostname]++
        → _dnsTotalByBssid[bssid]++
        → jos total >= 10 ja dominant >= 80%:
           → CaptivePortalDetected?.Invoke(bssid, dominant)
              → _alerts.Add("CaptivePortal", ...)
              → _alertDispatcher.SendAsync(...)
```

---

## 9. Behavioral IDS ja Honeypot

### BehaviorProfiler tietovuo

```
RecordTraffic(mac, vendor, bytes) [WifiAnalyzerEngine → GetAnalysisSnapshot]
RecordDns(mac, hostname)          [HiddenNodeTracker.ObservationRecorded]
RecordArp(mac)                    [DeviceScanner.ArpDetected]

RunChecks() [1/min] → tarkistaa 5 sääntöä:
  BaselineForCurrentHour() = saman tunnin 7 vrk historiakeskiarvo
  Jos sääntö laukaisee → AnomalyAlert → AnomalyDetected event
```

### Honeypot-tietovuo

```
Probe Request (subtype 4)
  → PassiveChannelScanner.ProbeRequestDetected?.Invoke(...)
  → WifiHoneypot.ProcessProbeRequest()
     → _decoySet.Contains(probedSsid) → HoneypotEvent
  → EventDetected?.Invoke(evt)
  → engine.HoneypotEventOccurred?.Invoke(evt)
  → Program.cs: AppLogger.Log(...)
  + engine._alertDispatcher.SendAsync("Honeypot", ..., severity=3)
  + engine._routerContainment.BlockMac(...)
  + engine._pcapRecorder.Start(...) jos EnableAutoCapture
```

---

## 10. Ulkoiset integraatiot

### MAC-esto aktivoituu

| Tapahtuma | Esto |
|---|---|
| Evil Twin (confidence ≥ 2) | ✓ |
| Deauth taso 3 (PMF tai broadcast) | ✓ |
| Honeypot-havainto | ✓ |
| Blacklist taso 3 | ✓ |
| ThreatIntel Malicious | ✓ |

### pfSense/OPNsense alias — käyttöönotto

1. Luo alias "wifi_blacklist" tyyppiä Host
2. Lisää palomuurisääntö: source=wifi_blacklist → BLOCK
3. Sovellus lisää MAC:it automaattisesti

---

## 11. Forensiikka ja PCAP

### Tiedostonimistandardi

```
capture_YYYYMMDD_HHMMSS_SYYTUNNUS_MACADDRESS.pcap
```

### Hakemiston automaattinen hallinta

```
RunPeriodicSideEffects (1/h):
  PcapRecorder.CleanupDirectory(dir, retentionDays, maxSizeMb)
    1. Poista > retentionDays vanhat
    2. Poista vanhimmat kunnes koko < maxSizeMb
```

---

## 12. Mesh-topologia ja roaming

### SVG-topologiakaavio värikoodit

| Väri | Merkitys |
|---|---|
| 🟢 Vihreä | Yhdistetty AP |
| 🔵 Sininen | RSSI ≥ -60 dBm |
| 🟡 Oranssi | RSSI -60…-75 dBm |
| 🔴 Punainen | RSSI < -75 dBm |

Nuolen paksuus: 1–5 px (1 roaming = 1 px, max 5 px).

---

## 13. Compliance-raportointi

### Arvosanan laskenta

| Status | Pisteet |
|---|---|
| Pass | 10 |
| Info | 8 |
| Warning | 5 |
| Fail | 0 |

`Score = rawScore / maxScore × 100`  
`Grade: A(≥90) B(≥80) C(≥70) D(≥60) F(<60)`

### Automaattinen aikataulutus

`ComplianceScheduleDay = 1` (maanantai) + `ComplianceScheduleHour = 8` → generoi klo 8 joka maanantai. Lähettää yhteenvedon Discord/Slackiin.

---

## 14. Säikeistys ja säikeenturvallisuus

### Säikeet

| Säie | Tehtävä |
|---|---|
| Pääsäie | UI · näppäimet · engine.Update() |
| ArpScanner | ARP-skannaus (Parallel.For, max 32) |
| mDNS | UDP multicast |
| SpinThread | Konsolispinneri |
| Thread pool | Skannaus, SSE, DPI, Speed, Webhookit, PCAP, RouterAPI, BehaviorPrune |
| Npcap | PacketCapture → OnPacketArrival |
| FileSystem | HotReload (WifiConfigWatcher) |

### Lukkohierarkia

| Lukko | Suojaa |
|---|---|
| `_lock` | `_aps`, `_knownSsidByBssid` |
| `_connectedLock` | `_connectedBssid` |
| `_alertLock` | `_alerts[]` |
| `_logFileLock` | `alerts.log` |
| `_sseLock` | SSE-asiakkaat |
| `_hourlyLock` | `_hourlyInterference{}` |
| `State.SlotResetLock` | BehaviorProfiler ring buffer -nollaus |
| `_loadLock` | OuiDatabase (double-checked locking) |
| `_softApLock` | WifiHoneypot SoftAP-tila |
| `_lock` (FileLogger) | Lokitiedoston kirjoitus |

---

## 15. Konsolinäkymä ja näppäinohjaus

### AP-rivin sarakkeet

```
[►/★] SSID | CH | BAND | RSSI-palkki | RSSI | Q | INT | TR | Vendor | Jitter | Score | Trendi | Sec
```

### Näppäinkomennot

| Näppäin | Toiminto |
|---|---|
| `S` | Pakota välitön skannaus |
| `R` | Nollaa liikennelaskurit |
| `E` | Vie raportit (JSON/CSV/HTML/Prometheus/Grafana) |
| `C` | Generoi compliance-raportti (PCI-DSS + ISO 27001) |
| `D` | ARP-skannaus (IP + MAC + hostname + vendor) |
| `A` | Hälytyshistorianäkymä |
| `X` | 2.4 GHz spektrinäkymä |
| `F` | SSID-suodatintila |
| `Tab` | Vaihda lajittelutila |
| `↑` / `↓` | AP-valinta |
| `Enter` | AP-detaljinäkymä |
| `Q` | WiFi-QR-koodi valitulle AP:lle |
| `Esc` | Sulje / peruuta |
| `Ctrl+C` | Lopeta |

---

## 16. Pisteytysalgoritmi

```
base  = (100 + Rssi)
      + log10(trafficBytes + 1) × 5.0
      + bandBonus (5 GHz: +3.0 · 6 GHz: +5.0)
      + 5.0 jos yhdistetty AP

penalty = co × CoChannelWeight
        + adj × AdjacentWeight
        × (1 + min(1.0, channelUtil / 100))

score = base − penalty
```

### Graadit

| Graadi | RSSI |
|---|---|
| A | ≥ −50 dBm |
| B | ≥ −60 dBm |
| C | ≥ −70 dBm |
| D | ≥ −80 dBm |
| F | < −80 dBm |

---


---

## 17. Vianmääritys

### "Npcap-laitteita ei löytynyt"

1. Varmista Npcap asennettu: https://npcap.com
2. Käynnistä Administrator-oikeuksilla
3. Tarkista ettei WinPcap-kompatibiliteettitila ole päällä

### "Sijainti-oikeus voi puuttua (Win11 24H2+)"

Asetukset → Yksityisyys → Sijainti → Päälle

### ThreatIntel pysyy pois päältä

1. Tarkista `EnableThreatIntel: true` on asetettu
2. Tarkista `OtxApiKey` tai `AbuseIpDbApiKey` on asetettu
3. Tarkista loki: etsi `[TI]` -merkinnät

### Dashboard ei päivity

1. Avaa `http://localhost:8765`
2. Tarkista `wifi_report.css` ja `wifi_report.js` samassa hakemistossa
3. F12 → Network: `/api/events` tilana "200 Pending"

### Behavioral IDS ei hälytä

Baseline aktivoituu vasta 4 h datan jälkeen. Tarkista loki: `[BID]`-merkinnät.

### PCAP-hakemisto kasvaa liian suureksi

Aseta `CaptureMaxDirectorySizeMb` ja `CaptureRetentionDays`. Siivous tapahtuu automaattisesti kerran tunnissa.

### RouterContainment ei estä

1. Tarkista URL ja kirjautumistiedot `wifi_config.json`:ssa
2. Loki: `[Unifi]`, `[pfSense]`, `[OPNsense]`
3. pfSense/OPNsense: varmista alias `wifi_blacklist` luotu ja kytketty sääntöön

### Grafana ei löydä metriikoita

1. `EnablePrometheusExport: true`
2. Prometheus scrape-config: `targets: ['localhost:8765']`
3. Kopioi `alert_rules.yml` Prometheuksen `rules/`-hakemistoon ja lisää `prometheus.yml`:ään: `rule_files: ['alert_rules.yml']`

---


