using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ManagedNativeWifi;
using SharpPcap;

namespace WifiAnalyzerPro
{
    public class WifiAnalyzerEngine : IDisposable
    {
        private static readonly JsonSerializerOptions JsonRead =
            new() { PropertyNameCaseInsensitive = true };

        private readonly WifiConfig     _cfg;
        private readonly AlertManager   _alerts;
        private readonly ChannelAnalyzer _channels;
        private readonly OuiDatabase    _oui;
        private readonly ReportExporter _exporter;
        private LongTermExporter        _lteExporter;

        // ── AP-tila ───────────────────────────────────────────────
        private readonly Dictionary<string, AccessPointSnapshot>    _aps    = new();
        private readonly object                                      _lock   = new();
        private readonly ConcurrentDictionary<string, long>         _trafficByBssid = new();
        private readonly ConcurrentDictionary<string, SignalStats>  _signalStats    = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, BeaconInfo>   _beaconIntervals= new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, string>       _securityByBssid= new(StringComparer.OrdinalIgnoreCase);
        // Passiivisen skannauksen kyvykkyystiedot (HT/VHT/HE, SNR, roaming) per BSSID
        private readonly ConcurrentDictionary<string, PassiveBeaconInfo> _passiveInfoByBssid =
            new(StringComparer.OrdinalIgnoreCase);
        // BSS Load Element (IE 11) -data kanavakohtaiseen häiriölaskentaan
        private readonly ChannelLoadTracker _channelLoad = new();

        // ── Uudet tietoturva- ja kapasiteettitrackerit ────────────
        private readonly DeauthTracker          _deauthTracker     = new();
        private readonly HiddenNodeTracker      _hiddenNodeTracker;
        private readonly DpiAnalyzer            _dpiAnalyzer;
        private readonly SecurityAlertDispatcher _alertDispatcher;
        private readonly PcapRecorder           _pcapRecorder;
        private readonly RouterContainment      _routerContainment;
        private readonly BehaviorProfiler       _behavior;
        private readonly ThreatIntelClient      _threatIntel;
        private readonly WifiHoneypot           _honeypot;
        private readonly EapolTracker           _eapolTracker = new();

        /// <summary>
        /// Laukaistaan kun uusi DPI-havainto (DNS/SNI) on tallennettu.
        /// Program.cs kytkee tähän webDashboard.PushDpiEvent() jotta
        /// inkrementaalinen SSE-push lähtee ilman täyttä snapshot-kierrosta.
        /// </summary>
        public event Action<TrafficObservation> DpiEventOccurred;
        /// <summary>Honeypot-havainto (Probe Request tai yhteys decoy-AP:hen).</summary>
        public event Action<HoneypotEvent>      HoneypotEventOccurred;
        /// <summary>Behavioral IDS -anomaliahälytys.</summary>
        public event Action<AnomalyAlert>       AnomalyDetected;

        // ── Evil Twin -seuranta ───────────────────────────────────
        private readonly Dictionary<string, string>                     _knownSsidByBssid = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, HashSet<string>>            _ssidToBssids     = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, (string Oui, string Security, int Channel)> _knownApDetails = new(StringComparer.OrdinalIgnoreCase);

        // ── Yhteys ────────────────────────────────────────────────
        private string ConnectedBssidSafe
        {
            get { lock (_connectedLock) return _connectedBssid; }
            set { lock (_connectedLock) _connectedBssid = value; }
        }
        private string _connectedBssid;
        private readonly object _connectedLock = new();
        private int    _prevConnectedRssi = 0;   // Roaming-seuranta: lähtöhetken RSSI

        // ── Pakettiprosessoijat (volatile array — lukitusvapaa luku, lukittu kirjoitus) ──
        private readonly object _processorLock = new();
        private volatile Action<byte[], DateTime>[] _processors =
            Array.Empty<Action<byte[], DateTime>>();

        // ── SharpPcap ─────────────────────────────────────────────
        private ICaptureDevice            _device;
        private PacketArrivalEventHandler _packetHandler;

        // ── Skannauslogiikka ──────────────────────────────────────
        private DateTime _lastActiveScanAttempt = DateTime.MinValue;
        private DateTime _lastBssRefresh        = DateTime.MinValue;
        private long     _lastScanFailureTicks  = 0;
        private DateTime LastScanFailure
        {
            get => new DateTime(Interlocked.Read(ref _lastScanFailureTicks));
            set => Interlocked.Exchange(ref _lastScanFailureTicks, value.Ticks);
        }
        private int _scanInProgress = 0;

        private readonly CancellationTokenSource _cts       = new();
        private int _stopOnce    = 0;
        private int _disposeOnce = 0;

        private volatile string _scanStatus        = "Skannaus: ei aloitettu";
        private volatile string _scanLastErrorHint = "";
        private volatile int    _scanLastOkInterfaces    = -1;
        private volatile int    _scanLastTotalInterfaces = -1;
        private long            _scanStartedTicks  = 0;
        private long            _scanFinishedTicks = 0;
        private volatile int    _scanTimeoutSec    = 6;

        private volatile int _scanOutcomeRaw = (int)ScanOutcome.None;
        private ScanOutcome ScanLastOutcome
        {
            get => (ScanOutcome)_scanOutcomeRaw;
            set => Interlocked.Exchange(ref _scanOutcomeRaw, (int)value);
        }

        private int      _dirty        = 1;
        private DateTime _lastJsonSave = DateTime.MinValue;
        private int      _trafficTick  = 0;
        private DateTime _lastLtePurge = DateTime.MinValue;

        private TimeSpan _minScanInterval;
        private TimeSpan _bssStaleThreshold;
        private TimeSpan _staleApTtl;

        private volatile string _bestChannel2G = "?";
        private volatile int   _rssiAlertThreshold;
        private volatile int   _rssiAlertClearThreshold;
        private static readonly char[] _spinnerSeq = { '|', '/', '-', '\\' };

        // Throttle: WLAN API -tietoturvakysely enintään kerran per 30 s
        private DateTime _lastSecurityRefresh  = DateTime.MinValue;
        private DateTime _lastBehaviorCheck  = DateTime.MinValue;
        private const int SecurityRefreshIntervalSec = 30;

        public bool   IsScanRunning => Interlocked.CompareExchange(ref _scanInProgress, 0, 0) == 1;
        public string BestChannel2G => _bestChannel2G;
        /// <summary>OUI-tietokanta — jaetaan DeviceScanner:ille vendor-hakua varten.</summary>
        public OuiDatabase OuiDb   => _oui;

        // ── Konstruktori ──────────────────────────────────────────

        public WifiAnalyzerEngine(WifiConfig cfg)
        {
            _cfg             = cfg;
            _alerts          = new AlertManager(cfg);
            _channels        = new ChannelAnalyzer(cfg);
            _oui             = new OuiDatabase();
            _exporter        = new ReportExporter(cfg);
            _minScanInterval   = TimeSpan.FromSeconds(cfg.MinScanIntervalSeconds);
            _bssStaleThreshold = TimeSpan.FromSeconds(cfg.BssStaleThresholdSeconds);
            _scanTimeoutSec    = cfg.ScanTimeoutSeconds;
            _staleApTtl        = TimeSpan.FromMinutes(cfg.StaleApMinutes);
            _rssiAlertThreshold      = cfg.RssiAlertThreshold;
            _rssiAlertClearThreshold = cfg.RssiAlertClearThreshold;

            // DpiAnalyzer ladataan kerran — blacklist.txt luetaan jos löytyy
            _dpiAnalyzer       = new DpiAnalyzer();
            _hiddenNodeTracker = new HiddenNodeTracker(_dpiAnalyzer);
            // Inkrementaaliset DPI-tapahtumat → DpiEventOccurred → Program.cs → WebDashboard
            _hiddenNodeTracker.ObservationRecorded += obs =>
            {
                DpiEventOccurred?.Invoke(obs);
                // Kriittinen blacklist-osuma → ulkoinen hälytys
                if (obs.IsBlacklisted && _alertDispatcher != null)
                    _alertDispatcher.SendAsync("Blacklist", obs.Name,
                        obs.BlacklistReason ?? "Blacklist-osuma", obs.BlacklistSeverity);

                // Uhkatiedustelu: tunnistamattomat, ei-blacklistatut domainit → TI API taustalla
                if (!obs.IsBlacklisted && obs.ServiceName == null && _threatIntel != null)
                    _threatIntel.EnqueueLookup(obs.Name, tiResult =>
                    {
                        int sev = tiResult.Level == ThreatLevel.Malicious ? 3 : 2;
                        string detail = $"TI ({tiResult.Source}): {tiResult.Level} — " +
                            (tiResult.PulseCount > 0 ? $"OTX pulses={tiResult.PulseCount} " : "") +
                            (tiResult.AbuseScore > 0 ? $"abuse={tiResult.AbuseScore}%" : "");
                        _alerts.Add("ThreatIntel", obs.Bssid ?? obs.SourceMac ?? "-", detail);
                        _alertDispatcher?.SendAsync("ThreatIntel", obs.Name, detail, sev);
                        if (sev == 3 && !string.IsNullOrEmpty(obs.SourceMac))
                            _routerContainment?.BlockMac(obs.SourceMac, $"ThreatIntel: {obs.Name}");
                        AppLogger.Log($"[TI] Hälytys: {obs.Name} ({tiResult.Level}) via {obs.SourceMac}");
                    });
            };
            _alertDispatcher = new SecurityAlertDispatcher(cfg);
            _pcapRecorder       = cfg.EnableAutoCapture ? new PcapRecorder(cfg) : null;
            _routerContainment  = new RouterContainment(cfg);
            _behavior        = new BehaviorProfiler();
            _threatIntel     = new ThreatIntelClient(cfg);
            _honeypot        = new WifiHoneypot(cfg.HoneypotSsids);
            _honeypot.EventDetected += evt =>
            {
                HoneypotEventOccurred?.Invoke(evt);
                _alertDispatcher?.SendAsync("Honeypot", evt.SourceMac,
                    evt.Detail, 3); // honeypot = aina kriittinen
            };

            if (cfg.EnableLongTermExport)
                try { _lteExporter = new LongTermExporter(cfg.SaveDirectory); }
                catch (Exception ex) { AppLogger.Log($"[Engine] LTE init: {ex.Message}"); }
        }

        // ── Julkinen API ──────────────────────────────────────────

        public string GetScanStatusLine(bool withSpinner)
        {
            long started  = Interlocked.Read(ref _scanStartedTicks);
            long finished = Interlocked.Read(ref _scanFinishedTicks);
            string when   = finished > 0 ? new DateTime(finished).ToString("HH:mm:ss")
                          : started  > 0 ? new DateTime(started).ToString("HH:mm:ss") : "--:--:--";
            string okInfo = (_scanLastOkInterfaces >= 0 && _scanLastTotalInterfaces >= 0)
                ? $"{_scanLastOkInterfaces}/{_scanLastTotalInterfaces} rajapintaa" : "—";
            char spin = withSpinner && IsScanRunning
                ? _spinnerSeq[(Environment.TickCount / 200) % _spinnerSeq.Length] : ' ';
            string hint = string.IsNullOrWhiteSpace(_scanLastErrorHint) ? "" : $" | {_scanLastErrorHint}";
            string outcome = ScanLastOutcome switch
            {
                ScanOutcome.None      => "N/A",
                ScanOutcome.Running   => "käynnissä",
                ScanOutcome.Ok        => "onnistui",
                ScanOutcome.Cancelled => "peruttu",
                ScanOutcome.Error     => "virhe",
                _                     => "?"
            };
            return $"{spin} {_scanStatus} | tulos: {outcome} ({okInfo}) | klo {when}{hint}";
        }

        public string GetOuiStatusLine()   => _oui.Status;
        public string GetBestChannelLine() => $"Suositeltu 2.4 GHz kanava: {_bestChannel2G}";

        // ── Käynnistys ────────────────────────────────────────────

        public void Start()
        {
            _oui.LoadIfNeeded();
            var devices = CaptureDeviceList.Instance;
            if (devices == null || devices.Count < 1)
                throw new Exception("Npcap-laitteita ei löytynyt.");

            _device = devices.FirstOrDefault(d =>
                ((d.Description ?? "").IndexOf("wi-fi",    StringComparison.OrdinalIgnoreCase) >= 0) ||
                ((d.Description ?? "").IndexOf("wlan",     StringComparison.OrdinalIgnoreCase) >= 0) ||
                ((d.Description ?? "").IndexOf("wireless", StringComparison.OrdinalIgnoreCase) >= 0))
                ?? devices.FirstOrDefault()
                ?? throw new Exception("Sopivaa verkkokorttia ei löytynyt.");

            _device.Open(DeviceModes.Promiscuous, 1000);

            _packetHandler = (_, e) =>
            {
                if (_cts.IsCancellationRequested) return;
                var raw = e.GetPacket();
                if (raw?.Data == null) return;
                byte[] frameData = raw.Data;

                // Lähde-MAC attribuointi
                string targetBssid = null;
                if (frameData.Length >= 12)
                {
                    string srcMac = string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                        frameData[6], frameData[7], frameData[8],
                        frameData[9], frameData[10], frameData[11]);
                    lock (_lock) { if (_aps.ContainsKey(srcMac)) targetBssid = srcMac; }
                }
                if (targetBssid == null) targetBssid = ConnectedBssidSafe;

                if (!string.IsNullOrEmpty(targetBssid))
                {
                    _trafficByBssid.AddOrUpdate(targetBssid, frameData.Length, (_, old) => old + frameData.Length);
                    if ((Interlocked.Increment(ref _trafficTick) % 50) == 0)
                        Interlocked.Exchange(ref _dirty, 1);
                }

                // Volatile array — lukitusvapaa luku, ei kopiota per paketti
                var procs = _processors;
                var ts    = raw.Timeval.Date;
                foreach (var proc in procs)
                    try { proc(frameData, ts); }
                    catch (Exception ex) { AppLogger.Log($"[Engine] Processor: {ex.Message}"); }
            };

            _device.OnPacketArrival += _packetHandler;
            _device.StartCapture();
        }

        public void AttachPacketProcessor(Action<byte[], DateTime> processor)
        {
            if (processor == null) return;
            lock (_processorLock)
            {
                var list = new List<Action<byte[], DateTime>>(_processors) { processor };
                _processors = list.ToArray();
            }
        }

        public void DetachPacketProcessor(Action<byte[], DateTime> processor)
        {
            if (processor == null) return;
            lock (_processorLock)
            {
                var list = new List<Action<byte[], DateTime>>(_processors);
                list.Remove(processor);
                _processors = list.ToArray();
            }
        }

        public void LoadHistoryFromReport(string path = "wifi_data.json")
        {
            try
            {
                if (!File.Exists(path)) return;
                var report = JsonSerializer.Deserialize<WifiFullReport>(
                    File.ReadAllText(path, System.Text.Encoding.UTF8), JsonRead);
                if (report?.History == null) return;
                int cap = Math.Max(20, _cfg.MaxHistoryPoints);
                foreach (var kv in report.History)
                {
                    var stats = _signalStats.GetOrAdd(kv.Key, _ => new SignalStats(cap));
                    int skip  = Math.Max(0, kv.Value.Count - cap);
                    stats.SeedFromHistory(kv.Value.Skip(skip));
                }
                AppLogger.Log($"[Engine] Historia ladattu: {report.History.Count} BSSID");
            }
            catch (Exception ex) { AppLogger.Log($"[Engine] Historia: {ex.Message}"); }
        }

        public void UpdateBeaconInterval(string bssid, int intervalTu)
        {
            if (string.IsNullOrWhiteSpace(bssid) || intervalTu <= 0) return;
            double ms = intervalTu * 1.024;
            _beaconIntervals[bssid] = new BeaconInfo
            {
                Bssid = bssid, IntervalTu = intervalTu, IntervalMs = Math.Round(ms, 1),
                // Beacon-intervalli kuvaa AP:n konfiguraatiota, ei kanavan käyttöastetta.
                // Oletus on 100 TU ≈ 102 ms. Poikkeamat voivat viitata virransäästöasetuksiin.
                LoadTag     = ms < 50  ? "Lyhyt intervalli (<50 ms)" :
                              ms > 200 ? "Pitkä intervalli (>200 ms)" : "Normaali (~100 ms)",
                LastUpdated = DateTime.Now
            };
        }

        public void UpdateSecurity(string bssid, string security)
        {
            if (string.IsNullOrWhiteSpace(bssid) || string.IsNullOrWhiteSpace(security)) return;
            _securityByBssid[bssid] = security;

            // KORJAUS: Päivitä myös _knownApDetails jos tietoturva oli aiemmin tuntematon.
            // Ilman tätä Evil Twin -vertailu käyttäisi "" vs "WPA2" -vertailua joka
            // IsSecurityDowngrade:ssa palauttaa aina false (tyhjä = tuntematon = ohitetaan).
            // Nyt kun passiivinen skannaus toimittaa tietoturvan myöhemmin, _knownApDetails
            // päivittyy välittömästi — seuraava sibling-tarkistus käyttää oikeaa tasoa.
            lock (_lock)
            {
                if (_knownApDetails.TryGetValue(bssid, out var det) &&
                    string.IsNullOrEmpty(det.Security))
                    _knownApDetails[bssid] = (det.Oui, security, det.Channel);
            }
        }

        /// <summary>
        /// Kirjaa BSS Load Element (IE 11) -datan ChannelLoadTracker:iin.
        /// Kutsutaan PassiveChannelScanner.BeaconReceived-tapahtumasta.
        /// </summary>
        public void UpdateChannelUtilization(string bssid, int channel,
            int? channelUtilization, int? stationCount = null)
        {
            _channelLoad.Update(bssid, channel, channelUtilization, stationCount);
        }

        /// <summary>
        /// Tallentaa koko PassiveBeaconInfo-tilannevedos BSSID:lle.
        /// Kutsutaan Program.cs:n BeaconReceived-handlerista jotta kyvykkyystiedot
        /// (HT/VHT/HE, SNR, roaming-standardit) ovat saatavilla GetAnalysisSnapshot():ssa.
        /// </summary>
        public void UpdatePassiveInfo(PassiveBeaconInfo info)
        {
            if (info == null || string.IsNullOrEmpty(info.Bssid)) return;
            _passiveInfoByBssid[info.Bssid] = info;
        }

        /// <summary>
        /// Rekisteröi PassiveChannelScanner:n laajennustapahtumien käsittelijät.
        /// Kutsutaan Program.cs:stä heti BeaconReceived-handlerin jälkeen.
        /// </summary>
        public void AttachPassiveScannerEvents(PassiveChannelScanner scanner)
        {
            if (scanner == null) return;

            scanner.DeauthReceived += evt =>
            {
                _deauthTracker.Record(evt);
            };

            scanner.RtsReceived += ch => _hiddenNodeTracker.RecordRts(ch);
            scanner.CtsReceived += ch => _hiddenNodeTracker.RecordCts(ch);

            scanner.DnsQueryDetected += (hostname, srcMac, bssid) =>
            {
                _hiddenNodeTracker.RecordDnsHostname(hostname, srcMac, bssid);
                if (!string.IsNullOrEmpty(srcMac))
                    _behavior?.RecordDns(srcMac, hostname);
            };

            scanner.TlsSniDetected += (sni, srcMac, bssid) =>
            {
                _hiddenNodeTracker.RecordTlsSni(sni, srcMac, bssid);
                if (!string.IsNullOrEmpty(srcMac))
                    _behavior?.RecordDns(srcMac, sni);
            };

            // PMF-tiedot välitetään DeauthTracker:ille heti kun Beacon on parsittu.
            // Näin DeauthStorm-hälytyksen yhteydessä tiedetään onko BSSID PMF-kykyinen.
            scanner.BeaconReceived += info =>
            {
                if (info != null && !string.IsNullOrEmpty(info.Bssid) &&
                    (info.PmfCapable || info.PmfRequired))
                    _deauthTracker.UpdatePmf(info.Bssid, info.PmfCapable, info.PmfRequired);
            };

            // Honeypot: Probe Request → WifiHoneypot
            scanner.ProbeRequestDetected += (srcMac, ssid, data, macOff) =>
            {
                _honeypot?.ProcessProbeRequest(data, macOff, srcMac);
                _behavior?.RecordArp(srcMac);
            };

            // EAPOL EtherType (0x888E) — behavioral PMKID-keräilymalli
            // Laskee kuinka monta eri BSSID:tä sama laite kättelee lyhyessä ajassa.
            // Ei parssi kryptografisia kenttiä (nonce, MIC, PMKID).
            scanner.EapolFrameDetected += (clientMac, bssidMac) =>
                _eapolTracker.RecordEapolFrame(clientMac, bssidMac);
        }

        /// <summary>Deauth-myrskyt prosessoidaan Update()-kutsun yhteydessä.</summary>
        private void ProcessDeauthAlerts()
        {
            var storms = _deauthTracker.DrainAlerts();
            foreach (var (bssid, msg, isBroadcast) in storms)
            {
                string type = isBroadcast ? "DeauthBroadcast" : "DeauthStorm";
                _alerts.Add(type, bssid, msg);

                // Ulkoinen hälytys — broadcast ja PMF-varmennettu = kriittisin
                int sev = isBroadcast || msg.Contains("VARMENNETTU") ? 3 :
                          msg.Contains("TODENN") ? 2 : 1;
                _alertDispatcher?.SendAsync(type, bssid, msg, sev);
                if (sev >= 3) _routerContainment?.BlockMac(bssid,
                    msg.Length > 60 ? msg.Substring(0, 60) : msg);

                // PCAP-nauhoitus kriittisestä deauth-hyökkäyksestä
                if (sev >= 3 && _pcapRecorder != null)
                    TriggerPcap(bssid, type);
            }
        }

        private void TriggerPcap(string bssid, string reason)
        {
            _pcapRecorder?.Start(bssid, reason, AttachPacketProcessor, DetachPacketProcessor);
        }

        public List<EapolTracker.EapolSummaryEntry> GetEapolSummary()
            => _eapolTracker.GetSummary();
        public string EapolStatus => _eapolTracker.Status;
        public ThreatIntelClient    GetThreatIntelClient() => _threatIntel;
        public string               ThreatIntelStatus     => _threatIntel?.Status ?? "";
        public string ExportComplianceReport(ComplianceReport r)
            => _exporter.ExportComplianceReport(r, _cfg.SaveDirectory ?? ".");
        public List<string>         GetRouterBlockLog()  => _routerContainment?.GetBlockLog() ?? new System.Collections.Generic.List<string>();
        public List<DeviceProfile>  GetDeviceProfiles()  => _behavior?.GetProfiles() ?? new System.Collections.Generic.List<DeviceProfile>();
        public List<HoneypotEvent>  GetHoneypotEvents()  => _honeypot?.GetRecentEvents() ?? new System.Collections.Generic.List<HoneypotEvent>();
        public bool  StartHoneypotSoftAp(string ssid = null) => _honeypot?.StartSoftAp(ssid) ?? false;
        public void  StopHoneypotSoftAp()                    => _honeypot?.StopSoftAp();
        public List<HiddenNodeStat> GetHiddenNodeStats() => _hiddenNodeTracker.GetStats();
        public List<DeauthEvent>    GetRecentDeauths()   => _deauthTracker.GetRecentEvents();
        public List<(string Host, DateTime LastSeen)> GetDnsHostnames()  => _hiddenNodeTracker.GetDnsHostnames();
        public List<(string Sni, DateTime LastSeen)>  GetTlsSnis()       => _hiddenNodeTracker.GetTlsSnis();

        // ── Update ────────────────────────────────────────────────

        // ── Tietoturvatyypin haku WLAN API:sta ───────────────────
        // EnumerateAvailableNetworks() palauttaa AuthenticationAlgorithm per SSID
        // välittömästi — ei tarvita beacon-kehyksiä pakettikaappauksesta.
        // Tätä käytetään fallbackina kun passiivinen skannaus ei ole vielä
        // toimittanut BSSID-kohtaista tietoa.
        private void RefreshSecurityFromWlanApi()
        {
            try
            {
                // SSID → tietoturvatyyppi -kartta WLAN API:sta
                var ssidSecurity = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var net in NativeWifi.EnumerateAvailableNetworks())
                {
                    string ssid = net.Ssid?.ToString();
                    if (string.IsNullOrEmpty(ssid)) continue;
                    string sec = MapAuthAlgorithm(net.AuthenticationAlgorithm, net.CipherAlgorithm);
                    if (sec != null && !ssidSecurity.ContainsKey(ssid))
                        ssidSecurity[ssid] = sec;
                }

                if (ssidSecurity.Count == 0) return;

                // Sovita SSID → BSSID ja päivitä _securityByBssid
                // Passiivisen kaappauksen antama BSSID-kohtainen tieto on
                // tarkempaa (esim. WPA2/3 mixed) joten se ei ylikirjoita.
                lock (_lock)
                {
                    foreach (var kv in _aps)
                    {
                        string bssid = kv.Key;
                        string ssid  = kv.Value.Ssid ?? "";
                        if (_securityByBssid.ContainsKey(bssid)) continue; // passiivinen tieto etusijalla
                        if (ssidSecurity.TryGetValue(ssid, out string sec))
                            _securityByBssid[bssid] = sec;
                    }
                }
            }
            catch (Exception ex) { AppLogger.Log($"[Security] WLAN API: {ex.Message}"); }
        }

        /// <summary>
        /// Muuntaa ManagedNativeWifi AuthenticationAlgorithm-arvon
        /// ohjelman sisäiseen tietoturvatunnisteeseen.
        ///
        /// Käytetään int-vertailua enumin nimien sijaan — Windows API:n
        /// DOT11_AUTH_ALGORITHM ja DOT11_CIPHER_ALGORITHM -vakioarvot eivät
        /// muutu ManagedNativeWifi-kirjaston versiosta riippumatta.
        ///
        /// DOT11_AUTH_ALGORITHM:
        ///   1 = Open, 2 = SharedKey/WEP
        ///   3 = WPA-Enterprise, 4 = WPA-Personal (PSK)
        ///   5 = WPA-None (ad hoc)
        ///   6 = WPA2-Enterprise (RSNA), 7 = WPA2-Personal (RSNA-PSK)
        ///   0x80000001 = IhvExtension (WPA3-SAE / OWE Windowsissa)
        ///
        /// DOT11_CIPHER_ALGORITHM:
        ///   0 = None, 1 = WEP40, 2 = TKIP, 4 = CCMP-128 (AES)
        ///   6 = GCMP-128, 8 = GCMP-256 (WPA3-tyypilliset)
        /// </summary>
        private static string MapAuthAlgorithm(
            AuthenticationAlgorithm auth, CipherAlgorithm cipher)
        {
            int a = (int)auth;
            int c = (int)cipher;

            if (a == 1) return "Open";          // DOT11_AUTH_ALGO_80211_OPEN
            if (a == 2) return "WEP";           // DOT11_AUTH_ALGO_80211_SHARED_KEY
            if (a == 3) return "WPA";           // DOT11_AUTH_ALGO_WPA (Enterprise)
            if (a == 4) return "WPA";           // DOT11_AUTH_ALGO_WPA_PSK (Personal)
            if (a == 5) return "WPA";           // DOT11_AUTH_ALGO_WPA_NONE (ad hoc)
            if (a == 6) return "WPA2-Ent";      // DOT11_AUTH_ALGO_RSNA (Enterprise)
            if (a == 7)                         // DOT11_AUTH_ALGO_RSNA_PSK (Personal)
            {
                // GCMP-128=6 tai GCMP-256=8 viittaa WPA3-yhteensopivaan laitteeseen
                if (c == 6 || c == 8) return "WPA2/3";
                return "WPA2";
            }
            if (a == unchecked((int)0x80000001)) return "WPA3"; // IhvExtension → WPA3-SAE / OWE
            return null;
        }

        public void Update()
        {
            if (_cts.IsCancellationRequested) return;
            var now = DateTime.Now;

            string connBeforeUpdate = ConnectedBssidSafe;
            try
            {
                foreach (var itf in NativeWifi.EnumerateInterfaces())
                {
                    var (result, conn) = NativeWifi.GetCurrentConnection(itf.Id);
                    if (result == ActionResult.Success && conn?.Bssid != null)
                        ConnectedBssidSafe = conn.Bssid.ToString();
                }
            }
            catch (UnauthorizedAccessException) { _scanLastErrorHint = "Vihje: Location-permission voi puuttua (Win11 24H2+)."; }
            catch (Exception ex) { AppLogger.Log($"[Update] Yhteys: {ex.Message}"); }

            // ── Roaming-jäljitys ─────────────────────────────────────
            string connNow = ConnectedBssidSafe;
            if (!string.IsNullOrEmpty(connBeforeUpdate) && !string.IsNullOrEmpty(connNow)
                && !string.Equals(connBeforeUpdate, connNow, StringComparison.OrdinalIgnoreCase))
            {
                int newRssi = 0;
                lock (_lock) { if (_aps.TryGetValue(connNow, out var ap)) newRssi = ap.Rssi; }
                _alerts.Add("Roaming", connNow,
                    $"Roaming: {connBeforeUpdate} ({_prevConnectedRssi} dBm) " +
                    $"→ {connNow} ({newRssi} dBm)");
                AppLogger.Log($"[Roaming] {connBeforeUpdate} → {connNow}");
            }
            if (!string.IsNullOrEmpty(connNow))
            {
                lock (_lock) { if (_aps.TryGetValue(connNow, out var ap)) _prevConnectedRssi = ap.Rssi; }
            }

            if (ShouldTriggerScan(now)) TryStartActiveScan(now, forced: false);

            IEnumerable<BssNetworkPack> all;
            try   { all = NativeWifi.EnumerateBssNetworks(); }
            catch (UnauthorizedAccessException) { _scanLastErrorHint = "Vihje: Location-permission voi puuttua."; all = Enumerable.Empty<BssNetworkPack>(); }
            catch (Exception ex) { AppLogger.Log($"[Update] BSS: {ex.Message}"); all = Enumerable.Empty<BssNetworkPack>(); }

            var dedup = new Dictionary<string, BssNetworkPack>(StringComparer.OrdinalIgnoreCase);
            foreach (var ap in all)
            {
                var key = ap.Bssid.ToString();
                if (!dedup.TryGetValue(key, out var existing) || ap.Rssi > existing.Rssi) dedup[key] = ap;
            }

            bool anyChange = false;
            var  pending   = new List<(string type, string bssid, string msg)>();

            lock (_lock)
            {
                foreach (var ap in dedup.Values)
                {
                    string bssid   = ap.Bssid.ToString();
                    string newSsid = ap.Ssid.ToString();
                    int    newRssi = ap.Rssi;
                    int    newCh   = ap.Channel;
                    string newPhy  = ap.PhyType.ToString();

                    if (!_aps.TryGetValue(bssid, out var entry))
                    { entry = new AccessPointSnapshot(); _aps[bssid] = entry; anyChange = true; }

                    if (entry.Ssid != newSsid || entry.Rssi != newRssi ||
                        entry.Channel != newCh || entry.Phy != newPhy) anyChange = true;

                    entry.Bssid = bssid; entry.Ssid = newSsid; entry.Rssi = newRssi;
                    entry.Channel = newCh; entry.Phy = newPhy; entry.LastSeen = now;

                    int cap    = Math.Max(20, _cfg.MaxHistoryPoints);
                    var stats  = _signalStats.GetOrAdd(bssid, _ => new SignalStats(cap));
                    stats.AddPoint(newRssi, now);

                    // ── SSID-seuranta ja Evil Twin ─────────────────
                    bool ssidKnown = _knownSsidByBssid.TryGetValue(bssid, out string knownSsid);
                    if (!ssidKnown)
                    {
                        _knownSsidByBssid[bssid] = newSsid;
                        _securityByBssid.TryGetValue(bssid, out string initSec);
                        _knownApDetails[bssid] = (OuiDatabase.Normalize(bssid), initSec ?? "", newCh);
                        if (!_ssidToBssids.ContainsKey(newSsid))
                            _ssidToBssids[newSsid] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        _ssidToBssids[newSsid].Add(bssid);
                        if (_cfg.AlertOnNewAp)
                            pending.Add(("NewAP", bssid, $"Uusi AP: '{newSsid}' RSSI {newRssi} dBm CH{newCh}"));
                    }
                    else if (!string.Equals(knownSsid, newSsid, StringComparison.Ordinal))
                    {
                        pending.Add(("EvilTwin", bssid, $"SSID muuttui! '{knownSsid}' → '{newSsid}'"));
                        _knownSsidByBssid[bssid] = newSsid; anyChange = true;
                    }
                    else
                    {
                        if (_ssidToBssids.TryGetValue(newSsid, out var siblings) && !siblings.Contains(bssid))
                        {
                            _ssidToBssids[newSsid].Add(bssid);
                            string newOui = OuiDatabase.Normalize(bssid);
                            _securityByBssid.TryGetValue(bssid, out string newSec);
                            newSec ??= "";

                            foreach (var sibBssid in siblings)
                            {
                                if (_knownApDetails.TryGetValue(sibBssid, out var sibDetails))
                                {
                                    // MAC-randomisaatiosuodatin
                                    bool sibRandom = _cfg.MacRandomizationFilter && AlertManager.IsMacRandomized(bssid);
                                    if (sibRandom) break;

                                    bool diffVendor = newOui != sibDetails.Oui &&
                                                      newOui.Length == 6 && sibDetails.Oui.Length == 6;

                                    // KORJAUS: Käytä sisaruksen ajantasaista tietoturvaa.
                                    // _knownApDetails tallennettiin ensimmäisellä havaitsemishetkellä,
                                    // jolloin tietoturva saattoi olla vielä tyhjä "".
                                    // UpdateSecurity() päivittää _knownApDetails:n kun tieto saapuu,
                                    // mutta varmuuden vuoksi tarkistetaan myös _securityByBssid.
                                    string sibSec = string.IsNullOrEmpty(sibDetails.Security) &&
                                                    _securityByBssid.TryGetValue(sibBssid, out string freshSibSec)
                                                    ? freshSibSec ?? ""
                                                    : sibDetails.Security;

                                    bool secDowngrade = AlertManager.IsSecurityDowngrade(sibSec, newSec);
                                    if (diffVendor || secDowngrade)
                                    {
                                        var parts = new List<string>(2);
                                        if (diffVendor)   parts.Add($"eri valmistaja ({newOui} vs {sibDetails.Oui})");
                                        if (secDowngrade) parts.Add($"heikompi salaus ({sibSec} → {newSec})");
                                        pending.Add(("EvilTwin", bssid,
                                            $"Epäilyttävä '{newSsid}': {string.Join(", ", parts)}"));
                                        break;
                                    }
                                }
                            }
                            _knownApDetails[bssid] = (newOui, newSec, newCh);
                        }
                    }

                    bool wasWeak = _alerts.IsWeakSignal(bssid);
                    if (!wasWeak && newRssi <= _cfg.RssiAlertThreshold)
                    {
                        _alerts.SetWeakSignal(bssid, true);
                        pending.Add(("WeakSignal", bssid,
                            $"Signaali heikko: '{newSsid}' {newRssi} dBm (raja {_cfg.RssiAlertThreshold} dBm)"));
                    }
                    else if (wasWeak && newRssi >= _cfg.RssiAlertClearThreshold)
                        _alerts.SetWeakSignal(bssid, false);
                }

                var stale = _aps.Where(kv => (now - kv.Value.LastSeen) > _staleApTtl)
                                .Select(kv => kv.Key).ToList();
                if (stale.Count > 0) anyChange = true;
                foreach (var key in stale)
                {
                    _aps.Remove(key);
                    _trafficByBssid.TryRemove(key, out _);
                    _signalStats.TryRemove(key, out _);
                    _oui.InvalidateCache(key);
                    _knownSsidByBssid.TryGetValue(key, out var oldSsid);
                    _knownSsidByBssid.Remove(key);
                    _knownApDetails.Remove(key);
                    _alerts.SetWeakSignal(key, false);
                    if (oldSsid != null && _ssidToBssids.TryGetValue(oldSsid, out var siblings))
                        siblings.Remove(key);
                }
            }

            foreach (var (t, b, m) in pending)
            {
                _alerts.Add(t, b, m);
                if (t == "EvilTwin")
                {
                    int conf = m.Contains("VARMENNETTU") ? 3 : m.Contains("heikompi") ? 2 : 1;
                    _alertDispatcher?.SendAsync("EvilTwin", b, m, conf);
                    if (conf >= 2 && _pcapRecorder != null) TriggerPcap(b, "EvilTwin");
                    if (conf >= 2) _routerContainment?.BlockMac(b,
                        $"Evil Twin: {m.Substring(0, Math.Min(60, m.Length))}");

                }
            }

            // Käsittele deauth-myrskyhälytykset
            ProcessDeauthAlerts();

            // Täydennä tietoturvatiedot WLAN API:sta niille AP:ille joille passiivinen
            // skannaus ei ole vielä toimittanut tietoa.
            // KORJAUS: Throttlattu — enintään kerran per SecurityRefreshIntervalSec.
            // Aiempi versio kutsui NativeWifi.EnumerateAvailableNetworks() joka kierroksella.
            if ((now - _lastSecurityRefresh).TotalSeconds >= SecurityRefreshIntervalSec)
            {
                RefreshSecurityFromWlanApi();
                _lastSecurityRefresh = now;
            }

            // Poista ChannelLoadTracker:sta pitkään näkymättömät AP:t (2× staleApTtl)
            _channelLoad.Prune(_staleApTtl + _staleApTtl);

            if (dedup.Count > 0) _lastBssRefresh = now;
            if (anyChange) Interlocked.Exchange(ref _dirty, 1);
        }

        // ── Analyysi ──────────────────────────────────────────────

        public List<AnalyzedAccessPoint> GetAnalysisSnapshot()
        {
            Dictionary<string, AccessPointSnapshot> apsCopy;
            lock (_lock)
            {
                apsCopy = new Dictionary<string, AccessPointSnapshot>(_aps.Count, StringComparer.OrdinalIgnoreCase);
                foreach (var kv in _aps)
                    apsCopy[kv.Key] = new AccessPointSnapshot
                    {
                        Bssid    = kv.Value.Bssid,    Ssid    = kv.Value.Ssid,
                        Rssi     = kv.Value.Rssi,     Channel = kv.Value.Channel,
                        Phy      = kv.Value.Phy,      LastSeen = kv.Value.LastSeen
                    };
            }

            var chCounts     = new Dictionary<int, int>();
            var wideChannels = new HashSet<int>();
            foreach (var ap in apsCopy.Values)
            {
                if (ap.Channel <= 0) continue;
                chCounts.TryGetValue(ap.Channel, out int cnt);
                chCounts[ap.Channel] = cnt + 1;
                if (ap.Channel <= 14 && !string.IsNullOrEmpty(ap.Phy))
                {
                    string p = ap.Phy.ToUpperInvariant();
                    if (p.Contains("N") || p.Contains("AC") || p.Contains("AX")) wideChannels.Add(ap.Channel);
                }
            }

            _bestChannel2G = ChannelAnalyzer.CalcBestChannel2G(chCounts, wideChannels);
            string connected = ConnectedBssidSafe;
            var    list      = new List<AnalyzedAccessPoint>(apsCopy.Count);

            // BSS Load -kanavakohtainen käyttöastekartta ChannelAnalyzer:lle
            var channelUtilMap = _channelLoad.GetPerChannelAverage();

            foreach (var kv in apsCopy)
            {
                string bssid = kv.Key;
                var    snap  = kv.Value;
                long   bytes = _trafficByBssid.TryGetValue(bssid, out var b) ? b : 0;
                double base_ = (100 + snap.Rssi) + (Math.Log10(bytes + 1) * 5.0);
                int    ch    = snap.Channel;

                // KORJAUS: Käytetään uutta ylikuormitusta joka ottaa BSS Load -datan huomioon.
                // Aiempi versio kutsui [Obsolete]-versiota beacon-intervalleilla.
                var (co, adj, penalty) = _channels.CalcInterference(ch, chCounts, channelUtilMap);

                var sigStats = _signalStats.TryGetValue(bssid, out var ss) ? ss : null;
                bool isConn  = !string.IsNullOrEmpty(connected) &&
                               string.Equals(bssid, connected, StringComparison.OrdinalIgnoreCase);
                _securityByBssid.TryGetValue(bssid, out string sec);

                // Kyvykkyydet passiivisesta skannauksesta (HT/VHT/HE, SNR, roaming)
                _passiveInfoByBssid.TryGetValue(bssid, out PassiveBeaconInfo passiveInfo);

                // Pieni bonus 5/6 GHz -kanaville: luonnostaan vähemmän ruuhkautuneita
                string band = ChannelAnalyzer.PhyToBand(snap.Phy, ch);
                double bandBonus = band switch { "5 GHz" => 3.0, "6 GHz" => 5.0, _ => 0.0 };

                // KORJAUS: Yhteyden bonus 0.01 → 5.0, jotta yhdistetty AP pysyy listan kärjessä
                // vaikka lähellä olisi marginaalisesti paremman signaalin AP.
                double score = base_ - penalty + bandBonus + (isConn ? 5.0 : 0.0);

                list.Add(new AnalyzedAccessPoint
                {
                    Bssid = bssid,
                    Ssid  = string.IsNullOrWhiteSpace(snap.Ssid) ? "<piilotettu>" : snap.Ssid,
                    Rssi  = snap.Rssi, Channel = ch,
                    Band  = band,
                    Phy   = snap.Phy, TrafficBytes = bytes,
                    Vendor = _oui.Lookup(bssid), IsConnected = isConn,
                    Security = sec ?? "?",
                    CoChannelCount = co, AdjacentOverlapCount = adj, InterferencePenalty = penalty,
                    SignalTrend  = sigStats?.Trend  ?? 0.0,
                    SignalJitter = sigStats?.Jitter ?? 0.0,
                    StabilityTag = ChannelAnalyzer.JitterToTag(sigStats?.Jitter ?? 0.0),
                    LastSeen = snap.LastSeen,
                    Score = score,
                    Grade = ChannelAnalyzer.RssiToGrade(snap.Rssi),
                    ChannelUtilization = _channelLoad.GetUtilization(bssid),
                    // ── Kyvykkyystiedot passiivisesta skannauksesta ──
                    PhyGeneration   = passiveInfo?.PhyGeneration,
                    MaxDataRateMbps = passiveInfo?.MaxDataRateMbps,
                    SpatialStreams  = passiveInfo?.SpatialStreams,
                    ChannelWidthMhz = passiveInfo?.ChannelWidthMhz,
                    SnrDb           = passiveInfo?.SnrDb,
                    Supports80211k  = passiveInfo?.Supports80211k ?? false,
                    Supports80211v  = passiveInfo?.Supports80211v ?? false,
                    Supports80211r  = passiveInfo?.Supports80211r ?? false,
                    PmfCapable      = passiveInfo?.PmfCapable  ?? false,
                    PmfRequired     = passiveInfo?.PmfRequired ?? false,
                });
            }

            var result = list.OrderByDescending(x => x.Score).ToList();

            // Mesh-suositus
            var ssidGrp = new Dictionary<string, List<AnalyzedAccessPoint>>(StringComparer.OrdinalIgnoreCase);
            foreach (var ap in result)
            {
                string k = ap.Ssid ?? "";
                if (!ssidGrp.ContainsKey(k)) ssidGrp[k] = new List<AnalyzedAccessPoint>();
                ssidGrp[k].Add(ap);
            }
            foreach (var grp in ssidGrp.Values)
            {
                if (grp.Count < 2) continue;
                int best = grp.Max(a => a.Rssi);
                foreach (var ap in grp)
                {
                    if (ap.IsConnected && ap.Rssi < best - 5) ap.MeshNote = $"⬆ Parempi AP ({best} dBm)";
                    else if (!ap.IsConnected && ap.Rssi == best) ap.MeshNote = "★ Paras AP tässä verkossa";
                }

                // Band steering -tunnistus: sama SSID sekä 2.4 GHz:llä että 5/6 GHz:llä
                var bands = grp.Select(a => a.Band ?? "").Distinct().ToList();
                bool has24 = bands.Any(b => b.Contains("2.4"));
                bool has5or6 = bands.Any(b => b.Contains("5") || b.Contains("6"));
                if (has24 && has5or6)
                {
                    // Tarkista onko sama valmistaja (OUI) → sama reititin
                    var vendors = grp.Select(a => a.Vendor ?? "")
                                     .Where(v => v != "Unknown").Distinct().ToList();
                    bool sameVendor = vendors.Count <= 1;
                    string tag = sameVendor ? " 📡 Band steering" : " 📡 Dual-band";
                    foreach (var ap in grp)
                        ap.MeshNote = string.IsNullOrEmpty(ap.MeshNote)
                            ? tag.Trim() : ap.MeshNote + tag;
                }
            }
            return result;
        }

        public void RunPeriodicSideEffects(List<AnalyzedAccessPoint> snap)
        {
            _channels.UpdateHourlyInterference(snap);
            CheckRoamSuggestion(snap);

            // Behavioral IDS: tarkista anomaliat kerran minuutissa
            if ((DateTime.Now - _lastBehaviorCheck).TotalMinutes >= 1)
            {
                _lastBehaviorCheck = DateTime.Now;
                // EAPOL-anomaliat (PMKID-keräily)
                var eapolAlerts = _eapolTracker.DrainAlerts();
                foreach (var ea in eapolAlerts)
                {
                    _alerts.Add("EapolAttack", ea.ClientMac, ea.Detail);
                    _alertDispatcher?.SendAsync("PMKID-keräily",
                        ea.ClientMac, ea.Detail, 2);
                    AppLogger.Log($"[EAPOL] {ea.Detail}");
                }
                var anomalies = _behavior?.RunChecks() ?? new System.Collections.Generic.List<AnomalyAlert>();
                foreach (var a in anomalies)
                {
                    _alerts.Add($"Anomaly_{a.Rule}", a.MacAddress, a.Detail);
                    _alertDispatcher?.SendAsync($"Anomaly: {a.Rule}", a.MacAddress,
                        $"{a.Detail} (Score: {a.Score}/100)",
                        a.Score >= 90 ? 3 : a.Score >= 60 ? 2 : 1);
                    AnomalyDetected?.Invoke(a);
                }
            }
        }

        private void CheckRoamSuggestion(List<AnalyzedAccessPoint> snap)
        {
            var ap = snap.FirstOrDefault(a => a.IsConnected);
            if (ap != null && ap.Rssi < -72 && !string.IsNullOrEmpty(ap.MeshNote))
                _alerts.Add("RoamSuggestion", ap.Bssid, $"Harkitse liittymistä: {ap.MeshNote}");
        }

        public List<AlertEntry> GetAlerts()          => _alerts.GetAll();
        public IReadOnlyList<AlertEntry> AlertSnapshot() => _alerts.Snapshot();
        public List<HourlyInterference> GetHourlyStats() => _channels.GetHourlyStats();
        public BeaconInfo GetBeaconInfo(string bssid) =>
            _beaconIntervals.TryGetValue(bssid, out var bi) ? bi : null;

        // ── Kaaviopiirto (delegoi SignalChartRenderer:ille) ────────

        public string[] GetSignalChart(string bssid, int width = 50)
        {
            _signalStats.TryGetValue(bssid, out var stats);
            return SignalChartRenderer.GetSignalChart(stats, bssid, GetBeaconInfo(bssid), width);
        }

        public string[] GetDailyRhythmChart(int barWidth = 20)
            => SignalChartRenderer.GetDailyRhythmChart(GetHourlyStats(), barWidth);

        public string[] GetChannelChart(List<AnalyzedAccessPoint> aps, int barWidth = 20)
            => SignalChartRenderer.GetChannelChart(aps, barWidth);

        public string[] GetSpectrumChart(List<AnalyzedAccessPoint> aps, int width = 60)
            => SignalChartRenderer.GetSpectrumChart(aps, width);

        // ── Tallennus ─────────────────────────────────────────────

        public void SaveJsonReportThrottled(
            List<AnalyzedAccessPoint> snap, List<AlertEntry> alertsSnap = null)
        {
            if (Interlocked.CompareExchange(ref _dirty, 0, 1) == 0) return;
            var now = DateTime.Now;
            if ((now - _lastJsonSave) < TimeSpan.FromSeconds(_cfg.SaveIntervalSeconds))
            { Interlocked.Exchange(ref _dirty, 1); return; }

            alertsSnap ??= GetAlerts();
            _exporter.ExportAll(snap, alertsSnap, BuildHistorySnapshot(), _bestChannel2G);

            if (_lteExporter != null)
            {
                _lteExporter.SaveSnapshot(snap, alertsSnap);
                if ((now - _lastLtePurge) > TimeSpan.FromHours(1))
                {
                    _lteExporter.PurgeOldRows(TimeSpan.FromHours(_cfg.JsonRetentionHours));
                    _lastLtePurge = now;
                }
            }
            _lastJsonSave = now;
        }

        public string ForceExport(
            List<AnalyzedAccessPoint> snap = null, List<AlertEntry> alertsSnap = null)
        {
            try
            {
                Interlocked.Exchange(ref _dirty, 1);
                _lastJsonSave  = DateTime.MinValue;
                snap       ??= GetAnalysisSnapshot();
                alertsSnap ??= GetAlerts();
                string msg = _exporter.ExportAll(snap, alertsSnap, BuildHistorySnapshot(), _bestChannel2G, "manual");
                _lteExporter?.SaveSnapshot(snap, alertsSnap);
                _lastJsonSave = DateTime.Now;
                Interlocked.Exchange(ref _dirty, 0);
                return msg;
            }
            catch (Exception ex) { return $"✗ Vienti epäonnistui: {ex.Message}"; }
        }

        public DashboardData BuildDashboardData(
            List<AnalyzedAccessPoint> snap, SpeedSample speed)
        {
            var allAlerts = _alerts.GetAll();
            var now       = DateTime.Now;

            // ── Hyökkäystason laskenta ──────────────────────────────
            int    attackLevel   = 0;
            string attackSummary = "";
            var recentDeauthAlerts = allAlerts
                .Where(a => (a.Type == "DeauthBroadcast" || a.Type == "DeauthStorm") &&
                            (now - a.Time).TotalMinutes < 5)
                .OrderByDescending(a => a.Time).ToList();

            if (recentDeauthAlerts.Any(a => a.Message.Contains("VARMENNETTU")))
            {
                attackLevel   = 3;
                attackSummary = recentDeauthAlerts
                    .First(a => a.Message.Contains("VARMENNETTU")).Message;
            }
            else if (recentDeauthAlerts.Any(a => a.Message.Contains("TODENN")))
            {
                attackLevel   = 2;
                attackSummary = recentDeauthAlerts.First(a => a.Message.Contains("TODENN")).Message;
            }
            else if (recentDeauthAlerts.Any())
            {
                attackLevel   = 1;
                attackSummary = recentDeauthAlerts.First().Message;
            }

            // ── Evil Twin -strukturointi ────────────────────────────
            var etAlerts = allAlerts
                .Where(a => a.Type == "EvilTwin" && (now - a.Time).TotalMinutes < 10)
                .OrderByDescending(a => a.Time)
                .Take(20).ToList();

            var evilTwinAlerts = etAlerts.Select(a =>
            {
                // Viesti: "Epäilyttävä 'SSID': eri valmistaja (OUI1 vs OUI2)"
                // tai "heikompi salaus (WPA2 → WPA)"
                // tai "*** VARMENNETTU HYÖKKÄYS: MFPR=1 ..."
                int conf = a.Message.Contains("VARMENNETTU") ? 3 :
                           a.Message.Contains("TODENN")      ? 2 : 1;
                string reason = a.Message.Contains("valmistaja") ? "Eri OUI-valmistaja" :
                                a.Message.Contains("salaus")     ? "Heikompi salaus" :
                                a.Message.Contains("PMF")        ? "PMF-protokollarikkomus" :
                                "Epäilyttävä SSID";
                // SSID otetaan heittomerkkien välistä viestistä
                string ssid = "";
                int q1 = a.Message.IndexOf('\'');
                int q2 = q1 >= 0 ? a.Message.IndexOf('\'', q1 + 1) : -1;
                if (q1 >= 0 && q2 > q1) ssid = a.Message.Substring(q1 + 1, q2 - q1 - 1);

                return new EvilTwinAlert
                {
                    Ssid            = ssid,
                    SuspectBssid    = a.Bssid,
                    LegitBssid      = "", // täytetään jos _ssidToBssids:stä saa haettua
                    ConfidenceLevel = conf,
                    Reason          = reason,
                    DetectedAt      = a.Time
                };
            }).ToList();

            var evilTwinBssids = etAlerts
                .Where(a => a.Bssid != null)
                .Select(a => a.Bssid)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            // ── DPI-liikennehavainnot ───────────────────────────────
            // Yhdistetty lista — DNS + TLS-SNI, blacklistatut ensin
            var trafficLog = _hiddenNodeTracker.GetObservations(10);

            // ── Viimeisin hälytykset ────────────────────────────────
            var recentAlerts = allAlerts.Count > 0
                ? allAlerts.GetRange(Math.Max(0, allAlerts.Count - 15), Math.Min(15, allAlerts.Count))
                : new List<AlertEntry>();

            return new DashboardData
            {
                Timestamp         = now,
                Networks          = snap,
                AlertCount        = allAlerts.Count,
                Speed             = speed,
                BestChannel       = _bestChannel2G,
                ScanStatus        = GetScanStatusLine(false),
                IsScanRunning     = IsScanRunning,
                RecentAlerts      = recentAlerts,
                RecentDeauths     = _deauthTracker.GetRecentEvents(60).Take(30).ToList(),
                ActiveAttackLevel = attackLevel,
                AttackSummary     = attackSummary,
                EvilTwinAlerts    = evilTwinAlerts,
                EvilTwinBssids    = evilTwinBssids,
                HiddenNodeStats   = _hiddenNodeTracker.GetStats(),
                TrafficLog        = trafficLog,
                // ── Uudet forensiikka- ja estopaneelit ────────────
                PcapActiveCount   = _pcapRecorder?.ActiveCount ?? 0,
                PcapRecentFiles   = GetRecentPcapFiles(10),
                RouterBlockLog    = (_routerContainment?.GetBlockLog() ?? new System.Collections.Generic.List<string>())
                                     .AsEnumerable().Reverse().Take(20).ToList(),
                EapolSummary      = _eapolTracker.GetSummary(),
                HoneypotEvents    = _honeypot?.GetRecentEvents(20) ?? new System.Collections.Generic.List<HoneypotEvent>()
            };
        }

        /// <summary>Listaa viimeisimmät PCAP-tiedostot tallennushakemistosta.</summary>
        private List<string> GetRecentPcapFiles(int max)
        {
            try
            {
                string dir = _cfg.CaptureDirectory ?? ".";
                if (!System.IO.Directory.Exists(dir)) return new System.Collections.Generic.List<string>();
                return new System.IO.DirectoryInfo(dir)
                    .GetFiles("*.pcap")
                    .OrderByDescending(f => f.LastWriteTime)
                    .Take(max)
                    .Select(f => $"[{f.LastWriteTime:HH:mm:ss}] {f.Name} ({f.Length / 1024} Kt)")
                    .ToList();
            }
            catch { return new System.Collections.Generic.List<string>(); }
        }

        // Välimuisti: säilytä edellinen snapshot per BSSID, korvaa vain muuttuneet
        private readonly Dictionary<string, List<SignalPoint>> _historyCache =
            new Dictionary<string, List<SignalPoint>>(StringComparer.OrdinalIgnoreCase);
        // KORJAUS: Erillinen lukko _historyCache:lle — BuildHistorySnapshot() kutsutaan
        // pääsilmukasta ilman _lock:ia, mutta _signalStats päivittyy taustasäikeestä.
        private readonly object _historyCacheLock = new();

        private Dictionary<string, List<SignalPoint>> BuildHistorySnapshot()
        {
            int cap = Math.Max(20, _cfg.MaxHistoryPoints);
            lock (_historyCacheLock)
            {
                foreach (var kv in _signalStats)
                {
                    try
                    {
                        if (kv.Value == null) continue;
                        // Ohita muuttumattomat BSSID:t — dirty-lippu kertoo onko uusia pisteitä
                        if (!kv.Value.IsDirty && _historyCache.ContainsKey(kv.Key)) continue;
                        var pts = kv.Value.GetHistory();
                        if (pts != null && pts.Length > 0)
                            _historyCache[kv.Key] = new List<SignalPoint>(
                                pts.Skip(Math.Max(0, pts.Length - cap)));
                        kv.Value.MarkClean();
                    }
                    catch (Exception ex) { AppLogger.Log($"[History] {kv.Key}: {ex.Message}"); }
                }
                // Poista poistettujen AP:iden välimuistimerkinnät
                var active = new HashSet<string>(
                    _signalStats.Keys, StringComparer.OrdinalIgnoreCase);
                foreach (var key in new List<string>(_historyCache.Keys))
                    if (!active.Contains(key)) _historyCache.Remove(key);
                return new Dictionary<string, List<SignalPoint>>(_historyCache, StringComparer.OrdinalIgnoreCase);
            }
        }

        // ── Skannaus ──────────────────────────────────────────────

        private bool ShouldTriggerScan(DateTime now)
        {
            if (IsScanRunning) return false;
            var lastFail = LastScanFailure;
            if (ScanLastOutcome == ScanOutcome.Error && lastFail != DateTime.MinValue &&
                (now - lastFail) > TimeSpan.FromSeconds(_cfg.ScanRetryAfterFailureSeconds)) return true;
            if ((now - _lastActiveScanAttempt) < _minScanInterval) return false;
            bool bssStale = _lastBssRefresh == DateTime.MinValue || (now - _lastBssRefresh) > _bssStaleThreshold;
            int apCount; lock (_lock) apCount = _aps.Count;
            return bssStale || apCount <= _cfg.MinApCountBeforeForceScan;
        }

        private void TryStartActiveScan(DateTime now, bool forced)
        {
            if (Interlocked.CompareExchange(ref _scanInProgress, 1, 0) != 0) return;
            _lastActiveScanAttempt   = now;
            _scanStatus              = forced ? "Skannaus: käynnissä (force)..." : "Skannaus: käynnissä...";
            ScanLastOutcome          = ScanOutcome.Running;
            _scanLastErrorHint       = forced ? "Force scan (S)" : "";
            _scanLastOkInterfaces    = -1;
            _scanLastTotalInterfaces = -1;
            Interlocked.Exchange(ref _scanStartedTicks,  now.Ticks);
            Interlocked.Exchange(ref _scanFinishedTicks, 0);
            int total = 0;
            try { total = NativeWifi.EnumerateInterfaces().Count(); } catch { }
            _scanLastTotalInterfaces = total;
            int timeoutSec = _scanTimeoutSec;

            Task.Run(async () =>
            {
                try
                {
                    var scanned     = await NativeWifi.ScanNetworksAsync(
                        TimeSpan.FromSeconds(timeoutSec), _cts.Token);
                    int ok          = scanned?.Count() ?? 0;
                    _scanLastOkInterfaces = ok;
                    ScanLastOutcome = ScanOutcome.Ok;
                    _scanStatus     = "Skannaus: valmis";
                    Interlocked.Exchange(ref _scanFinishedTicks, DateTime.Now.Ticks);
                    int newSec = total > 0 && ok < total
                        ? Math.Min(10, timeoutSec + 2)
                        : Math.Max(6,  timeoutSec - 1);
                    Volatile.Write(ref _scanTimeoutSec, newSec);
                }
                catch (UnauthorizedAccessException)
                {
                    ScanLastOutcome    = ScanOutcome.Error;
                    _scanStatus        = "Skannaus: virhe";
                    _scanLastErrorHint = "Location-permission voi puuttua (Win11 24H2+).";
                    LastScanFailure    = DateTime.Now;
                    Interlocked.Exchange(ref _scanFinishedTicks, DateTime.Now.Ticks);
                }
                catch (OperationCanceledException)
                {
                    ScanLastOutcome = ScanOutcome.Cancelled;
                    _scanStatus     = "Skannaus: peruttu";
                    Interlocked.Exchange(ref _scanFinishedTicks, DateTime.Now.Ticks);
                }
                catch (Exception ex)
                {
                    ScanLastOutcome = ScanOutcome.Error;
                    _scanStatus     = "Skannaus: virhe";
                    LastScanFailure = DateTime.Now;
                    AppLogger.Log($"[Scan] {ex.Message}");
                    Interlocked.Exchange(ref _scanFinishedTicks, DateTime.Now.Ticks);
                }
                finally { Interlocked.Exchange(ref _scanInProgress, 0); }
            });
        }

        public void ForceScan()
        {
            if (_cts.IsCancellationRequested || IsScanRunning) return;
            TryStartActiveScan(DateTime.Now, forced: true);
        }

        /// <summary>Ulkoinen hälytyksen lisäys (PassiveChannelScanner.ThreatDetected jne.)</summary>
        public void AddAlert(string type, string bssid, string message)
            => _alerts.Add(type, bssid, message);

        public void ResetTraffic() { _trafficByBssid.Clear(); Interlocked.Exchange(ref _dirty, 1); }

        /// <summary>Soveltaa hot-reload-konfiguraation lennossa.</summary>
        public void ApplyConfig(WifiConfig newCfg)
        {
            if (newCfg == null) return;
            _minScanInterval   = TimeSpan.FromSeconds(newCfg.MinScanIntervalSeconds);
            _bssStaleThreshold = TimeSpan.FromSeconds(newCfg.BssStaleThresholdSeconds);
            _staleApTtl        = TimeSpan.FromMinutes(newCfg.StaleApMinutes);
            Volatile.Write(ref _scanTimeoutSec, newCfg.ScanTimeoutSeconds);
            Volatile.Write(ref _rssiAlertThreshold,      newCfg.RssiAlertThreshold);
            Volatile.Write(ref _rssiAlertClearThreshold, newCfg.RssiAlertClearThreshold);
            _alerts.ApplyConfig(newCfg);
            _alertDispatcher?.Apply(newCfg);
            _routerContainment?.Apply(newCfg);
            _threatIntel?.Apply(newCfg);
            AppLogger.Log($"[HotReload] RssiAlert={newCfg.RssiAlertThreshold} dBm, " +
                          $"ScanInterval={newCfg.MinScanIntervalSeconds} s, " +
                          $"TI={(newCfg.EnableThreatIntel ? "on" : "off")}, " +
                          $"Discord={(string.IsNullOrEmpty(newCfg.DiscordWebhookUrl) ? "off" : "on")}");
        }
        public void RequestStop() { try { _cts.Cancel(); } catch (Exception ex) { AppLogger.Log($"[Engine] ReqStop: {ex.Message}"); } }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _stopOnce, 1) != 0) return;
            try { _cts.Cancel(); } catch { }
            try { if (_device != null && _packetHandler != null) _device.OnPacketArrival -= _packetHandler; } catch { }
            try { _device?.StopCapture(); } catch { }
            try { _device?.Close(); } catch { }
            try { (_device as IDisposable)?.Dispose(); } catch { }
            try { _lteExporter?.Dispose(); } catch { }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposeOnce, 1) != 0) return;
            Stop();
            try { _cts.Dispose(); } catch { }
        }
    }
}
