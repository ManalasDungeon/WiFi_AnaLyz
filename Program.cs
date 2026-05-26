using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    // ── UI-tila omaan luokkaansa (testattavissa) ──────────────────
    internal enum SortMode { Score, Rssi, Channel, Ssid, Security }

    internal class ConsoleUiState
    {
        public int      SelectedIndex    = 0;
        public bool     DetailView;
        public bool     AlertView;
        public int      AlertScrollOffset;
        public string   SsidFilter       = "";
        public bool     FilterMode;
        public bool     SpectrumView;
        public SortMode Sort             = SortMode.Score;

        public string SortLabel => Sort switch
        {
            SortMode.Rssi     => "RSSI↓",
            SortMode.Channel  => "CH↑",
            SortMode.Ssid     => "SSID",
            SortMode.Security => "Turva",
            _                 => "Score↓"
        };
    }

    class Program
    {
        private static volatile bool _keepRunning  = true;
        private static volatile bool _shuttingDown;
        // Yksi lukko — ei sisäkkäistä (KORJAUS)
        private static readonly object _consoleLock = new();
        private static ConsoleUiState  _ui          = new();
        private static int             _lastWinW;
        private static int             _lastWinH;
        private static volatile int    _frameW      = 120;
        private static readonly DateTime _startTime = DateTime.Now;

        // KORJAUS: Tarkistaa myös Linux/macOS-terminaalit
        private static readonly bool _useEmoji = DetectEmojiSupport();

        private static readonly string _tableHeader =
            FitCol("SSID", 19) + "| CH | BAND  |RSSI BAR  |RSSI| Q |INT|TR| " +
            FitCol("Vendor", 16) + "|Jitter| Score | Trendi | Sec";

        static void Main()
        {
            try
            {
                Console.OutputEncoding = System.Text.Encoding.UTF8;
                Console.InputEncoding  = System.Text.Encoding.UTF8;
            }
            catch { }
            Console.Title = "Wi-Fi Analyzer Pro";

            var    cfg   = WifiConfigLoader.Load();
            string gwIp  = GetDefaultGateway();
            string logDir = string.IsNullOrWhiteSpace(cfg.SaveDirectory) ? "." : cfg.SaveDirectory;
            AppLogger.Configure(new FileLogger(Path.Combine(logDir, "wifi_analyzer.log")));

            using var engine         = new WifiAnalyzerEngine(cfg);
            using var passiveScanner = new PassiveChannelScanner();
            using var speedMonitor   = new SpeedMonitor();
            // OuiDatabase jaetaan moottorin ja laitetunnistuksen välillä — ei duplikaattilatausta
            using var deviceScanner  = new DeviceScanner(engine.OuiDb);
            // KORJAUS: Anna oikea dataProvider /api/data-endpointille niin se palauttaa
            // tuoretta dataa eikä aina viimeistä Push()-kutsun snapshotia.
            using var webDashboard   = new WebDashboard(cfg,
                () => engine.BuildDashboardData(engine.GetAnalysisSnapshot(), speedMonitor.GetLatest()));

            string   lastMsg      = "";
            DateTime lastMsgUntil = DateTime.MinValue;

            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel      = true;
                _shuttingDown = true;
                _keepRunning  = false;
                engine.RequestStop();
            };

            int       fullRefreshMs = cfg.FullRefreshMs;
            const int spinnerMs     = 200;
            int       maxRows       = cfg.MaxConsoleRows;

            const int rowScan   = 1; const int rowOui  = 2; const int rowCh   = 3;
            const int rowAlerts = 4; const int rowCmd  = 8; const int rowHeader= 9;
            const int rowSep    = 10;const int rowData  = 11;
            int       rowChart  = rowData + maxRows + 1;

            try
            {
                var configWarnings = WifiConfigLoader.Validate(cfg);
                if (configWarnings.Count > 0)
                {
                    Console.WriteLine("Konfiguraatiovaroitukset:");
                    foreach (var w in configWarnings) Console.WriteLine("  " + w);
                    Console.WriteLine("  (Paina Enter jatkaaksesi tai Ctrl+C peruuttaaksesi)");
                    try { Console.ReadLine(); } catch { }
                }

                engine.Start();
                string saveDir = string.IsNullOrWhiteSpace(cfg.SaveDirectory) ? "." : cfg.SaveDirectory;
                engine.LoadHistoryFromReport(Path.Combine(saveDir, "wifi_data.json"));
                // KORJAUS: Käytetään Start(gwIp, cfg) -versiota — aiempi Start(gwIp, url)
                // ohitti SpeedTestIntervalMinutes-konfiguraation kokonaan ([Obsolete]-versio).
                speedMonitor.Start(gwIp, cfg);
                deviceScanner.StartMdnsListener();
                webDashboard.Start();

                // Konfiguraation hot-reload
                using var cfgWatcher = new WifiConfigWatcher("wifi_config.json",
                    newCfg => engine.ApplyConfig(newCfg));

                passiveScanner.BeaconReceived += info =>
                {
                    if (info.BeaconIntervalTu > 0) engine.UpdateBeaconInterval(info.Bssid, info.BeaconIntervalTu);
                    if (!string.IsNullOrEmpty(info.Security)) engine.UpdateSecurity(info.Bssid, info.Security);
                    if (info.ChannelUtilization.HasValue)
                        engine.UpdateChannelUtilization(info.Bssid, info.Channel,
                            info.ChannelUtilization, info.StationCount);
                    // Kyvykkyystiedot (HT/VHT/HE, SNR, roaming) — tallennetaan kokonaisena
                    engine.UpdatePassiveInfo(info);
                };

                // Rekisteröi Deauth/RTS/CTS/DNS/TLS-tapahtumat
                engine.AttachPassiveScannerEvents(passiveScanner);

                // Inkrementaaliset DPI-tapahtumat menevät suoraan SSE-kanavalle
                // ilman täyttä snapshot-kierrosta — matala viive, ei blokaa moottoria
                engine.DpiEventOccurred += obs => webDashboard?.PushDpiEvent(obs);
                engine.AttachPacketProcessor((data, ts) => passiveScanner.ProcessPacket(data, ts));

                Console.Clear();
                Console.WriteLine($"Wi-Fi Analyzer Pro | Ctrl+C lopettaa | RSSI-raja: {cfg.RssiAlertThreshold} dBm | Dashboard: {webDashboard.Status}");
                for (int i = 1; i <= rowChart + 20; i++) Console.WriteLine();
                WriteAt(0, rowHeader, _tableHeader);

                // Spinneri erillisessä säikeessä — ei blokoi UI-kierrosta (KORJAUS)
                var spinThread = new Thread(() =>
                {
                    while (_keepRunning)
                    {
                        if (!_shuttingDown)
                        {
                            lock (_consoleLock)
                            {
                                try
                                {
                                    string line = engine.GetScanStatusLine(withSpinner: true);
                                    int    w    = Math.Max(10, Console.WindowWidth - 1);
                                    WriteAt(0, rowScan, (line.Length > w ? line.Substring(0, w) : line).PadRight(w));
                                }
                                catch { }
                            }
                        }
                        Thread.Sleep(spinnerMs);
                    }
                }) { IsBackground = true, Name = "Spinner" };
                spinThread.Start();

                while (_keepRunning)
                {
                    engine.Update();
                    var results    = engine.GetAnalysisSnapshot();
                    var alertsSnap = engine.GetAlerts();
                    engine.RunPeriodicSideEffects(results);

                    if (!string.IsNullOrEmpty(_ui.SsidFilter))
                        results = results.Where(a =>
                            (a.Ssid ?? "").IndexOf(_ui.SsidFilter, StringComparison.OrdinalIgnoreCase) >= 0
                        ).ToList();

                    // Tab-lajittelu (Score-järjestys on jo GetAnalysisSnapshot():n oletus)
                    results = _ui.Sort switch
                    {
                        SortMode.Rssi     => results.OrderByDescending(a => a.Rssi).ToList(),
                        SortMode.Channel  => results.OrderBy(a => a.Channel).ToList(),
                        SortMode.Ssid     => results.OrderBy(a => a.Ssid ?? "",
                                                StringComparer.OrdinalIgnoreCase).ToList(),
                        SortMode.Security => results.OrderBy(a => SecLevel(a.Security)).ToList(),
                        _                 => results  // Score — jo järjestetty
                    };

                    if (_ui.SelectedIndex >= results.Count)
                        _ui.SelectedIndex = Math.Max(0, results.Count - 1);

                    engine.SaveJsonReportThrottled(results, alertsSnap);

                    // Push dashboard update
                    webDashboard.Push(engine.BuildDashboardData(results, speedMonitor.GetLatest()));

                    // ── UI-piirto ── (KORJAUS: ei sisäkkäistä lukkoa, ei Thread.Sleep lukolla)
                    lock (_consoleLock)
                    {
                        _frameW = Math.Max(40, Console.WindowWidth - 1);

                        if (Console.WindowWidth != _lastWinW || Console.WindowHeight != _lastWinH)
                        {
                            _lastWinW = Console.WindowWidth; _lastWinH = Console.WindowHeight;
                            Console.Clear();
                            WriteAt(0, rowHeader, _tableHeader);
                            WriteAt(0, rowSep, new string('─', Math.Min(_frameW, 120)));
                        }

                        try { Console.CursorVisible = false; } catch { }

                        WriteAt(0, rowOui, engine.GetOuiStatusLine());
                        WriteAt(0, rowCh,  $"{engine.GetBestChannelLine()}  |  Passiv: {passiveScanner.Status}  |  Nopeus: {speedMonitor.Status}  |  Web: {webDashboard.Status}");

                        string cmdLine = _ui.FilterMode
                            ? $"SUODATIN: [{_ui.SsidFilter}]  Esc=peruuta"
                            : $"[S]Scan [R]Reset [E]Vie [C]Compliance [D]ARP [F]Suodatin [A]Hälytykset [X]Spektri [Tab]Lajittelu:{_ui.SortLabel} [Enter]Tiedot [Q]QR [Esc]Takaisin";
                        if (DateTime.Now < lastMsgUntil && !string.IsNullOrWhiteSpace(lastMsg))
                            cmdLine += "  » " + lastMsg;
                        WriteAt(0, rowCmd, cmdLine);

                        // Hälytykset (3 viimeistä)
                        if (alertsSnap.Count > 0 && !_ui.AlertView)
                        {
                            WriteAt(0, rowAlerts, $"⚠ HÄLYTYKSET ({alertsSnap.Count} kpl) — [A] näytä kaikki:");
                            int shown = 0;
                            for (int ai = alertsSnap.Count - 1; ai >= 0 && shown < 3; ai--, shown++)
                                WriteAt(0, rowAlerts + 1 + shown,
                                    $"  [{alertsSnap[ai].Time:HH:mm:ss}] [{alertsSnap[ai].Type}] {alertsSnap[ai].Message}");
                        }
                        else if (!_ui.AlertView)
                            for (int r = rowAlerts; r < rowAlerts + 4; r++) WriteAt(0, r, new string(' ', _frameW));

                        // Hälytyssivu
                        if (_ui.AlertView)
                        {
                            int pageSize  = rowChart - rowAlerts - 2;
                            int maxScroll = Math.Max(0, alertsSnap.Count - pageSize);
                            _ui.AlertScrollOffset = Math.Max(0, Math.Min(_ui.AlertScrollOffset, maxScroll));
                            WriteAt(0, rowAlerts,
                                $"⚠ HÄLYTYSHISTORIA ({alertsSnap.Count}) " +
                                $"[{_ui.AlertScrollOffset + 1}–{Math.Min(_ui.AlertScrollOffset + pageSize, alertsSnap.Count)}]" +
                                " — [↑↓] selaa  [A]/[Esc] sulje:");
                            for (int ai = 0; ai < pageSize; ai++)
                            {
                                int absIdx = alertsSnap.Count - 1 - _ui.AlertScrollOffset - ai;
                                if (absIdx < 0) { WriteAt(0, rowAlerts + 1 + ai, new string(' ', _frameW)); continue; }
                                var a = alertsSnap[absIdx];
                                WriteAt(0, rowAlerts + 1 + ai,
                                    $"  {AlertIcon(a.Type)} [{a.Time:HH:mm:ss}] [{a.Type,-14}] {FitCol(a.Message, _frameW - 38)}");
                            }
                            for (int r = rowAlerts + 1 + pageSize; r < rowData + maxRows; r++)
                                WriteAt(0, r, new string(' ', _frameW));
                        }
                        else
                        {
                            // Spektrinäkymä [X]
                            if (_ui.SpectrumView)
                            {
                                int row = rowData;
                                string[] spec = engine.GetSpectrumChart(results, Math.Min(70, Console.WindowWidth - 12));
                                for (int ci = 0; ci < Math.Min(spec.Length, maxRows + 8); ci++)
                                    WriteAt(0, row++, spec[ci]);
                                while (row < rowData + maxRows + 2) WriteAt(0, row++, new string(' ', _frameW));
                            }
                            else
                            {
                                // Datarivi-lista
                                int row = rowData; int idx = 0;
                                var dlist = results.Take(maxRows).ToList();
                                foreach (var ap in dlist)
                                {
                                    bool isSel = idx == _ui.SelectedIndex;
                                    string grade = ap.Grade ?? "F";
                                    string bar   = RssiBar(ap.Rssi, 10);
                                    string secIc = SecurityIcon(ap.Security);
                                    string trend = ap.SignalTrend > 1.5  ? $"↑{ap.SignalTrend:+0.0}" :
                                                   ap.SignalTrend < -1.5 ? $"↓{ap.SignalTrend:0.0}"  : "→ 0.0";
                                    string mesh  = string.IsNullOrEmpty(ap.MeshNote) ? "" : " " + ap.MeshNote;
                                    string line  = string.Format(
                                        "{0}{1}{2}|{3,3} |{4,6} |{5} {6,4}| {7} |{8,3}|{9}| {10}|±{11,4:F1}|{12,6:F1} | {13}{14}|{15}",
                                        isSel ? "►" : " ", ap.IsConnected ? "★" : " ", FitCol(ap.Ssid ?? "", 18),
                                        ap.Channel, ap.Band, bar, ap.Rssi, grade,
                                        ap.CoChannelCount + ap.AdjacentOverlapCount,
                                        ap.TrafficBytes > 0 ? "▶" : " ",
                                        FitCol(ap.Vendor ?? "Unknown", 16),
                                        ap.SignalJitter, ap.Score, trend, mesh, secIc);

                                    ConsoleColor pFg = Console.ForegroundColor, pBg = Console.BackgroundColor;
                                    if (isSel) { Console.BackgroundColor = ConsoleColor.DarkBlue; Console.ForegroundColor = ConsoleColor.White; }
                                    else Console.ForegroundColor =
                                        grade == "A" ? ConsoleColor.Green  :
                                        grade == "B" ? ConsoleColor.Cyan   :
                                        grade == "C" ? ConsoleColor.Yellow :
                                        grade == "D" ? ConsoleColor.Red    : ConsoleColor.DarkRed;
                                    try
                                    {
                                        int safeRow = Math.Max(0, Math.Min(row, Console.BufferHeight - 1));
                                        Console.SetCursorPosition(0, safeRow);
                                        Console.Write(line.Length > _frameW ? line.Substring(0, _frameW) : line.PadRight(_frameW));
                                    }
                                    catch (Exception ex) { AppLogger.Log($"[UI] Row {row}: {ex.Message}"); }
                                    finally { Console.ForegroundColor = pFg; Console.BackgroundColor = pBg; }
                                    row++; idx++;
                                }
                                while (row < rowData + maxRows) WriteAt(0, row++, new string(' ', _frameW));

                                // Detaljinäkymä
                                if (_ui.DetailView && _ui.SelectedIndex < dlist.Count)
                                {
                                    var selAp = dlist[_ui.SelectedIndex];
                                    var bi    = engine.GetBeaconInfo(selAp.Bssid);

                                    // ── Perusrivi ──────────────────────────────────────
                                    WriteAt(0, rowChart, $"  ── {selAp.Ssid} ({selAp.Bssid}) CH{selAp.Channel} | " +
                                        $"{selAp.Rssi} dBm | {selAp.Grade} | Jitter ±{selAp.SignalJitter:F1} | " +
                                        $"Beacon: {(bi != null ? $"{bi.IntervalMs} ms ({bi.LoadTag})" : "N/A")} | " +
                                        $"{SecurityIcon(selAp.Security)} {selAp.Security}");

                                    // ── Kyvykkyystiedot ────────────────────────────────
                                    int capRow = rowChart + 1;
                                    string gen   = selAp.PhyGeneration ?? "—";
                                    string rate  = selAp.MaxDataRateMbps.HasValue
                                        ? $"{selAp.MaxDataRateMbps} Mbps max" : "—";
                                    string mimo  = selAp.SpatialStreams.HasValue
                                        ? $"{selAp.SpatialStreams}×{selAp.SpatialStreams} MIMO" : "—";
                                    string width = selAp.ChannelWidthMhz.HasValue
                                        ? $"{selAp.ChannelWidthMhz} MHz" : "—";
                                    string snr   = selAp.SnrDb.HasValue
                                        ? $"SNR {selAp.SnrDb} dB" : "SNR —";
                                    string roam  = string.Join(" ",
                                        selAp.Supports80211k ? new[]{"11k"} : Array.Empty<string>(),
                                        selAp.Supports80211v ? new[]{"11v"} : Array.Empty<string>(),
                                        selAp.Supports80211r ? new[]{"11r"} : Array.Empty<string>())
                                        .Trim();
                                    // PMF-tila
                                    string pmfStr = selAp.PmfRequired ? "PMF vaatii (turvallinen)" :
                                                    selAp.PmfCapable  ? "PMF tukee" : "PMF ei tuettu";
                                    WriteAt(0, capRow,
                                        $"  {gen} | {rate} | {mimo} | {width} | {snr}" +
                                        (roam.Length > 0 ? $" | Roaming: {roam}" : "") +
                                        $" | {pmfStr}");

                                    string[] sig = engine.GetSignalChart(selAp.Bssid, Math.Min(60, Console.WindowWidth - 12));
                                    for (int ci = 0; ci < sig.Length; ci++) WriteAt(0, capRow + 1 + ci, sig[ci]);

                                    int rh0 = capRow + 1 + sig.Length + 1;
                                    string[] rh = engine.GetDailyRhythmChart();
                                    for (int ci = 0; ci < Math.Min(rh.Length, 10); ci++) WriteAt(0, rh0 + ci, rh[ci]);

                                    int sp0 = rh0 + Math.Min(rh.Length, 10) + 1;
                                    var spd = speedMonitor.GetLatest();
                                    if (spd != null)
                                    {
                                        WriteAt(0, sp0, $"  Nopeus — Ping: {(spd.PingMs < 0 ? "N/A" : $"{spd.PingMs:F0} ms")} | DL: {spd.ThroughputKBs:F1} KB/s | GW: {spd.Gateway}");
                                        string[] pc = speedMonitor.GetPingChart(Math.Min(50, Console.WindowWidth - 20));
                                        for (int ci = 0; ci < Math.Min(pc.Length, 6); ci++) WriteAt(0, sp0 + 1 + ci, pc[ci]);
                                    }
                                    else WriteAt(0, sp0, "  Nopeus: ei mittauksia vielä");

                                    // ── Deauth-tapahtumat ──────────────────────────────
                                    var deauths = engine.GetRecentDeauths()
                                        .Where(d => string.Equals(d.SenderBssid, selAp.Bssid,
                                                   StringComparison.OrdinalIgnoreCase))
                                        .Take(3).ToList();
                                    if (deauths.Count > 0)
                                    {
                                        int dr = sp0 + 8;
                                        WriteAt(0, dr++, $"  Deauth-tapahtumat ({deauths.Count} viimeisin):");
                                        foreach (var d in deauths)
                                            WriteAt(0, dr++, $"    [{d.Time:HH:mm:ss}] {(d.IsDeauth ? "Deauth" : "Disassoc")} → {d.TargetMac} ({d.ReasonText})");
                                    }
                                }
                                else if (!_ui.DetailView)
                                {
                                    string[] ch = engine.GetChannelChart(results);
                                    for (int ci = 0; ci < ch.Length; ci++) WriteAt(0, rowChart + ci, ch[ci]);
                                    int dr = rowChart + ch.Length + 1;
                                    var dl = deviceScanner.GetDevices();
                                    WriteAt(0, dr++, dl.Count > 0
                                        ? $"  Havaitut laitteet ({dl.Count}):"
                                        : "  Verkkolaitteet: [D] käynnistää ARP-skannauksen");
                                    foreach (var d in dl.Take(5))
                                        WriteAt(0, dr++, string.Format("    {0,-16} {1,-18} {2,-14} [{3}]",
                                            d.IpAddress,
                                            d.Hostname?.Length > 17 ? d.Hostname.Substring(0, 16) + "…" : (d.Hostname ?? "--"),
                                            d.Vendor?.Length > 13  ? d.Vendor.Substring(0, 12) + "…"  : (d.Vendor ?? ""),
                                            d.Source));
                                }
                            }
                        }

                        WriteAt(0, rowChart + 30,
                            $"[{DateTime.Now:HH:mm:ss}  Up: {DateTime.Now - _startTime:hh\\:mm\\:ss}  AP: {results.Count}" +
                            (string.IsNullOrEmpty(_ui.SsidFilter) ? "" : $"  F: {_ui.SsidFilter}") +
                            // KORJAUS: Käytä _useEmoji-lippua — kovakoodatut emojit eivät toimi
                            // terminaaleissa joissa emoji-tuki puuttuu.
                            (_useEmoji
                                ? "  |  A≥-50 B≥-60 C≥-70 D≥-80 F<-80  |  WPA3=🔒 WPA2=🔑 WPA=⚠ Open=❌]"
                                : "  |  A>=-50 B>=-60 C>=-70 D>=-80 F<-80  |  WPA3=[3] WPA2=[2] WPA=[W] Open=[ ]]"));

                        try { Console.CursorVisible = true; } catch { }
                    } // lock loppu — Thread.Sleep lukkon ulkopuolella

                    // Näppäinsilmukka — lukitonta aluetta (KORJAUS: ei lock täällä)
                    bool force = false;
                    int  until = Environment.TickCount + fullRefreshMs;
                    while (_keepRunning && Environment.TickCount < until && !force)
                    {
                        try
                        {
                            if (!Console.KeyAvailable) { Thread.Sleep(50); continue; }
                            var key = Console.ReadKey(intercept: true);
                            switch (key.Key)
                            {
                                case ConsoleKey.S:
                                    engine.ForceScan();
                                    lastMsg = "Force scan käynnistetty"; lastMsgUntil = DateTime.Now.AddSeconds(3); force = true; break;
                                case ConsoleKey.R:
                                    engine.ResetTraffic();
                                    lastMsg = "Traffic nollattu"; lastMsgUntil = DateTime.Now.AddSeconds(3); force = true; break;
                                case ConsoleKey.E:
                                    lastMsg = engine.ForceExport(results, alertsSnap);
                                    lastMsgUntil = DateTime.Now.AddSeconds(5); force = true; break;
                                case ConsoleKey.C:
                                    // Compliance-raportti [C]
                                    Task.Run(() =>
                                    {
                                        try
                                        {
                                            var compReport = ComplianceChecker.Check(
                                                results,
                                                alertsSnap,
                                                engine.GetEapolSummary());
                                            string path = engine.ExportComplianceReport(compReport);
                                            lastMsg = $"Compliance {compReport.OverallGrade} ({compReport.Score}/100): {System.IO.Path.GetFileName(path)}";
                                        }
                                        catch (Exception ex) { lastMsg = $"Compliance-virhe: {ex.Message}"; }
                                        lastMsgUntil = DateTime.Now.AddSeconds(8);
                                    });
                                    lastMsg = "Generoidaan compliance-raporttia...";
                                    lastMsgUntil = DateTime.Now.AddSeconds(3); break;
                                case ConsoleKey.A:
                                    _ui.AlertView         = !_ui.AlertView;
                                    _ui.AlertScrollOffset = 0;
                                    _ui.DetailView        = false;
                                    force = true; break;
                                case ConsoleKey.X:
                                    _ui.SpectrumView = !_ui.SpectrumView;
                                    _ui.DetailView   = false;
                                    lastMsg = _ui.SpectrumView ? "Spektrinäkymä käytössä" : "Listanäkymä";
                                    lastMsgUntil = DateTime.Now.AddSeconds(2); force = true; break;
                                case ConsoleKey.D:
                                    if (!deviceScanner.IsScanning)
                                    {
                                        string sub = gwIp.Length > 0
                                            ? string.Join(".", gwIp.Split('.'), 0, 3)
                                            : "192.168.1";
                                        deviceScanner.StartArpScan(sub);
                                        lastMsg = $"ARP-skannaus ({sub}.x)"; lastMsgUntil = DateTime.Now.AddSeconds(5);
                                    }
                                    else { lastMsg = "ARP käynnissä..."; lastMsgUntil = DateTime.Now.AddSeconds(3); }
                                    force = true; break;
                                case ConsoleKey.P:
                                    lastMsg = $"Passiivisesti: {passiveScanner.GetBeacons().Count} AP:ta";
                                    lastMsgUntil = DateTime.Now.AddSeconds(4); force = true; break;
                                case ConsoleKey.UpArrow:
                                    if (_ui.AlertView) _ui.AlertScrollOffset++;
                                    else { if (_ui.SelectedIndex > 0) _ui.SelectedIndex--; _ui.DetailView = false; }
                                    force = true; break;
                                case ConsoleKey.DownArrow:
                                    if (_ui.AlertView) _ui.AlertScrollOffset = Math.Max(0, _ui.AlertScrollOffset - 1);
                                    else { _ui.SelectedIndex++; _ui.DetailView = false; }
                                    force = true; break;
                                case ConsoleKey.Enter:
                                    _ui.DetailView = !_ui.DetailView; force = true; break;
                                case ConsoleKey.Tab:
                                    // Tab kierrättää lajittelutilaa
                                    _ui.Sort = (SortMode)(((int)_ui.Sort + 1) % 5);
                                    lastMsg = $"Lajittelu: {_ui.SortLabel}";
                                    lastMsgUntil = DateTime.Now.AddSeconds(2);
                                    force = true; break;
                                                                    
                                case ConsoleKey.Q:
                                {
                                    var qrAp = (_ui.DetailView && _ui.SelectedIndex < results.Count)
                                        ? results[_ui.SelectedIndex] : null;
                                    if (qrAp != null)
                                    {
                                        // WifiQrCode.ShowInConsole kysyy salasanan sisäisesti
                                        // ReadMasked()-metodilla — ei tarvitse erillistä kyselyä.
                                        lock (_consoleLock) WifiQrCode.ShowInConsole(qrAp.Ssid, qrAp.Security);
                                        lastMsg = "QR-koodi — paina Esc sulkeaksesi";
                                        lastMsgUntil = DateTime.Now.AddSeconds(15);
                                    }
                                    else { lastMsg = "[Enter] avataksesi tiedot, sitten [Q] QR-koodi"; lastMsgUntil = DateTime.Now.AddSeconds(3); }
                                    force = true; break;
                                }
                                case ConsoleKey.Escape:
                                    _ui.DetailView  = false; _ui.FilterMode = false;
                                    _ui.AlertView   = false; _ui.SpectrumView = false;
                                    _ui.SsidFilter  = ""; force = true; break;
                                case ConsoleKey.F:
                                    _ui.FilterMode = !_ui.FilterMode; _ui.SsidFilter = "";
                                    lastMsg = _ui.FilterMode ? "Suodatin: kirjoita SSID (Esc peruuttaa)" : "Suodatin poistettu";
                                    lastMsgUntil = DateTime.Now.AddSeconds(_ui.FilterMode ? 10 : 2); force = true; break;
                                case ConsoleKey.Backspace:
                                    if (_ui.FilterMode && _ui.SsidFilter.Length > 0)
                                    {
                                        _ui.SsidFilter = _ui.SsidFilter.Substring(0, _ui.SsidFilter.Length - 1);
                                        lastMsg = "Suodatin: " + (_ui.SsidFilter.Length > 0 ? _ui.SsidFilter : "(tyhjä)");
                                        lastMsgUntil = DateTime.Now.AddSeconds(10); force = true;
                                    }
                                    break;
                                default:
                                    if (_ui.FilterMode && key.KeyChar >= 32)
                                    {
                                        _ui.SsidFilter += key.KeyChar;
                                        lastMsg = "Suodatin: " + _ui.SsidFilter;
                                        lastMsgUntil = DateTime.Now.AddSeconds(10);
                                        _ui.SelectedIndex = 0; force = true;
                                    }
                                    break;
                            }
                        }
                        catch (Exception ex) { AppLogger.Log($"[Key] {ex.Message}"); }
                    }
                }
            }
            catch (Exception ex)
            {
                lock (_consoleLock) Console.WriteLine("\nVIRHE: " + ex.Message);
            }
            finally
            {
                _shuttingDown = true;
                lock (_consoleLock)
                {
                    try
                    {
                        Console.ResetColor();
                        int safeRow = Math.Min(Console.BufferHeight - 4, Console.WindowHeight - 4);
                        safeRow = Math.Max(safeRow, 0);
                        Console.SetCursorPosition(0, safeRow);
                        int w = Math.Max(10, Console.WindowWidth - 1);
                        Console.WriteLine(new string(' ', w));
                        Console.WriteLine(new string(' ', w));
                        Console.SetCursorPosition(0, safeRow);
                        Console.WriteLine("Pysäytetään...");
                    }
                    catch { Console.WriteLine("\nPysäytetään..."); }
                }
                webDashboard.Stop();
                engine.Stop();
                lock (_consoleLock)
                {
                    try { Console.ResetColor(); } catch { }
                    Console.WriteLine("Valmis.");
                }
            }
        }

        // ── Apufunktiot ───────────────────────────────────────────

        private static string GetDefaultGateway()
        {
            try
            {
                foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                    foreach (var gw in ni.GetIPProperties().GatewayAddresses)
                    {
                        string a = gw.Address.ToString();
                        if (a != "0.0.0.0" && !a.Contains(':')) return a;
                    }
                }
            }
            catch (Exception ex) { AppLogger.Log($"[GW] {ex.Message}"); }
            return "192.168.1.1";
        }

        /// <summary>
        /// KORJAUS: Tarkistaa myös Linux/macOS-terminaalit TERM_PROGRAM- ja
        /// COLORTERM-ympäristömuuttujien avulla.
        /// </summary>
        private static bool DetectEmojiSupport()
        {
            try
            {
                if (Console.OutputEncoding.CodePage != 65001) return false;

                // Windows 10+
                if (Environment.OSVersion.Platform == PlatformID.Win32NT &&
                    Environment.OSVersion.Version.Major >= 10) return true;

                // Linux/macOS: NO_EMOJI poistaa käytöstä, COLORTERM tai TERM_PROGRAM = tuki
                string noEmoji    = Environment.GetEnvironmentVariable("NO_EMOJI");
                if (noEmoji == "1" || noEmoji == "true") return false;
                string termProg   = Environment.GetEnvironmentVariable("TERM_PROGRAM") ?? "";
                string colorTerm  = Environment.GetEnvironmentVariable("COLORTERM")    ?? "";
                string term       = Environment.GetEnvironmentVariable("TERM")         ?? "";
                return termProg.Length > 0 || colorTerm.Length > 0 ||
                       term.Contains("xterm") || term.Contains("256color");
            }
            catch { return false; }
        }

        private static void WriteAt(int col, int row, string text)
        {
            try
            {
                int safeRow = Math.Max(0, Math.Min(row, Console.BufferHeight - 1));
                Console.SetCursorPosition(col, safeRow);
                int w = Math.Max(10, _frameW - col);
                Console.Write((text.Length > w ? text.Substring(0, w) : text).PadRight(w));
            }
            catch { }
        }

        private static string BarStr(int filled, int total)
            => new string('█', Math.Max(0, filled)) + new string('░', Math.Max(0, total - filled));

        private static string RssiBar(int rssi, int width = 10)
        {
            double fill = Math.Max(0.0, Math.Min(1.0, (rssi + 100) / 70.0));
            return BarStr((int)(fill * width), width);
        }

        private static string SecurityIcon(string sec) => (sec ?? "") switch
        {
            var s when s.Contains("3")   => _useEmoji ? "🔒" : "[3]",
            var s when s.Contains("Ent") => _useEmoji ? "🏢" : "[E]",
            var s when s.Contains("2")   => _useEmoji ? "🔑" : "[2]",
            var s when s == "WPA"        => _useEmoji ? "⚠"  : "[W]",
            var s when s == "Open"       => _useEmoji ? "❌" : "[ ]",
            _                            => " ? "
        };

        private static string AlertIcon(string type) => type switch
        {
            "EvilTwin"       => _useEmoji ? "🚨" : "[!]",
            "WeakSignal"     => _useEmoji ? "📶" : "[~]",
            "NewAP"          => _useEmoji ? "🆕" : "[+]",
            "RoamSuggestion" => _useEmoji ? "📍" : "[>]",
            _                => _useEmoji ? "ℹ"  : "[ ]"
        };

        private static int SecLevel(string sec)
        {
            if (sec == null) return 0;
            if (sec.Contains("3"))   return 4;
            if (sec.Contains("Ent")) return 3;
            if (sec.Contains("2"))   return 2;
            if (sec == "WPA")        return 1;
            if (sec == "WEP")        return 1;
            return 0;
        }

        private static string FitCol(string s, int len)
        {
            if (s == null) s = "";
            return s.Length > len ? s.Substring(0, len - 1) + "…" : s.PadRight(len);
        }
    }
}
