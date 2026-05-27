using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Paikallinen HTTP-palvelin (System.Net.HttpListener — ei NuGet-riippuvuuksia).
    /// Portit: WebDashboardPort (HTML+SSE) ja optionaalisesti Prometheus /metrics.
    ///
    /// Endpointit:
    ///   GET /             → wifi_report.html (viimeisin raportti)
    ///   GET /api/data     → JSON (viimeisin snapshot)
    ///   GET /api/events   → Server-Sent Events (reaaliaikainen päivitys)
    ///   GET /metrics      → Prometheus-teksti (jos EnablePrometheusExport)
    /// </summary>
    public class WebDashboard : IDisposable
    {
        private readonly WifiConfig _cfg;
        private readonly Func<DashboardData> _dataProvider;
        private HttpListener _listener;
        private CancellationTokenSource _cts;
        private Task _serveTask;
        private Task _keepAliveTask;

        // SSE-asiakkaat. Lukko otetaan VAIN listan modifioinnissa ja snapshotin
        // ottamisessa — ei verkkokirjoituksen aikana (KORJAUS).
        private readonly List<HttpListenerResponse> _sseClients = new();
        private readonly object                     _sseLock    = new();

        private volatile DashboardData _lastData;

        public string Status    { get; private set; } = "Ei käynnissä";
        public bool   IsRunning => _listener?.IsListening == true;

        public WebDashboard(WifiConfig cfg, Func<DashboardData> dataProvider)
        {
            _cfg          = cfg;
            _dataProvider = dataProvider;
        }

        public void Start()
        {
            int port = _cfg.WebDashboardPort;
            if (port <= 0) { Status = "Web-dashboard pois käytöstä (port=0)"; return; }

            try
            {
                _listener = new HttpListener();
                _listener.Prefixes.Add($"http://localhost:{port}/");
                _listener.Start();
                _cts           = new CancellationTokenSource();
                _serveTask     = Task.Run(() => ServeLoopAsync(_cts.Token));
                _keepAliveTask = Task.Run(() => KeepAliveLoopAsync(_cts.Token));
                Status = $"http://localhost:{port}/";
                AppLogger.Log($"[Web] Dashboard: {Status}");
            }
            catch (Exception ex)
            {
                Status = $"Ei käynnistynyt: {ex.Message}";
                AppLogger.Log($"[Web] Käynnistys: {ex.Message}");
            }
        }

        // SSE-asetukset
        private const int MaxSseClients   = 10;     // Enintään N samanaikaista SSE-yhteyttä
        private const int WriteTimeoutMs  = 3000;   // Per-kirjoitus max 3 s ennen kuin asiakas poistetaan
        private const int DpiRateLimitMs  = 400;    // Min väli DPI-pushien välillä (max ~2.5/s)
        private const int DpiQueueMax     = 50;     // Jonoon mahtuvan DPI-tapahtumia max

        // DPI: erillinen puskuri inkrementaalisia event-pusheja varten
        private readonly ConcurrentQueue<string> _dpiQueue  = new();
        private int _lastDpiFlushTick = 0;

        // Push-inflight guard
        private int _pushInFlight = 0;

        /// <summary>
        /// Kutsutaan kun uusi snapshot on valmis — lähettää täyden SSE-päivityksen.
        /// Taustasäikeessä (Task.Run), ei blokaa pääsilmukkaa.
        /// </summary>
        public void Push(DashboardData data)
        {
            _lastData = data;
            byte[] buf;
            try
            {
                string evt = $"data: {JsonSerializer.Serialize(data)}\n\n";
                buf = Encoding.UTF8.GetBytes(evt);
            }
            catch (Exception ex)
            {
                AppLogger.Log($"[Web] Push serialize: {ex.Message}");
                return;
            }

            lock (_sseLock) { if (_sseClients.Count == 0) return; }

            // Salli vain yksi täysi push kerrallaan
            if (Interlocked.CompareExchange(ref _pushInFlight, 1, 0) != 0) return;

            _ = Task.Run(() =>
            {
                try   { PushCore(buf); }
                catch (Exception ex) { AppLogger.Log($"[Web] PushCore: {ex.Message}"); }
                finally { Interlocked.Exchange(ref _pushInFlight, 0); }
            });
        }

        /// <summary>
        /// Lähettää inkrementaalisen DPI-tapahtuman (event:dpi) ilman täyttä snapshotia.
        /// Rate-limitoitu: nopea datavirta puskuroidaan ja puretaan yhdellä kirjoituksella.
        /// Ei jää kiinni _pushInFlight-lippuun — DPI ja täysi push ovat riippumattomia.
        /// </summary>
        public void PushDpiEvent(TrafficObservation obs)
        {
            if (obs == null) return;
            lock (_sseLock) { if (_sseClients.Count == 0) return; }

            try
            {
                string json = JsonSerializer.Serialize(obs);
                // SSE named event: selain käyttää evt.addEventListener('dpi', handler)
                string frame = $"event: dpi\ndata: {json}\n\n";

                // Puskuroidaan jonoon — poistetaan vanhimmat jos jono täynnä
                if (_dpiQueue.Count >= DpiQueueMax) _dpiQueue.TryDequeue(out _);
                _dpiQueue.Enqueue(frame);
            }
            catch (Exception ex) { AppLogger.Log($"[Web] PushDpiEvent serialize: {ex.Message}"); return; }

            // Tarkista rate limit
            int now  = Environment.TickCount;
            int last = Interlocked.CompareExchange(ref _lastDpiFlushTick, 0, 0);
            if (now - last < DpiRateLimitMs) return; // jonoon tallennettiin, ei vielä flushata

            Interlocked.Exchange(ref _lastDpiFlushTick, now);

            // Flushaa koko jono yhdellä kirjoituksella taustasäikeessä
            _ = Task.Run(() =>
            {
                try
                {
                    var frames = new List<string>();
                    while (_dpiQueue.TryDequeue(out var f)) frames.Add(f);
                    if (frames.Count == 0) return;
                    byte[] buf = Encoding.UTF8.GetBytes(string.Concat(frames));
                    PushCore(buf);
                }
                catch (Exception ex) { AppLogger.Log($"[Web] DpiFlush: {ex.Message}"); }
            });
        }

        /// <summary>
        /// Kirjoittaa buf kaikille SSE-asiakkaille. Jokainen kirjoitus saa WriteTimeoutMs
        /// aikarajan — hitaat tai katkenneet asiakkaat poistetaan välittömästi.
        /// </summary>
        private void PushCore(byte[] buf)
        {
            HttpListenerResponse[] snapshot;
            lock (_sseLock) snapshot = _sseClients.ToArray();
            if (snapshot.Length == 0) return;

            List<HttpListenerResponse> dead = null;
            foreach (var resp in snapshot)
            {
                try
                {
                    // WriteAsync + Wait(timeout) — ei jää kiinni hitaaseen asiakkaaseen
                    var task = resp.OutputStream.WriteAsync(buf, 0, buf.Length);
                    if (!task.Wait(WriteTimeoutMs))
                    {
                        AppLogger.Log("[Web] SSE write timeout — asiakas poistetaan");
                        (dead ??= new List<HttpListenerResponse>()).Add(resp);
                        continue;
                    }
                    resp.OutputStream.Flush();
                }
                catch { (dead ??= new List<HttpListenerResponse>()).Add(resp); }
            }

            if (dead != null)
                lock (_sseLock)
                    foreach (var d in dead)
                    {
                        _sseClients.Remove(d);
                        try { d.Close(); } catch { }
                    }
        }

        // ── HTTP-palvelusilmukka ──────────────────────────────────

        private async Task ServeLoopAsync(CancellationToken ct)
        {
            // KORJAUS: Käytetään GetContextAsync:ia — Stop() → listener.Stop() heittää
            // HttpListenerException:in, joka päättää silmukan puhtaasti.
            while (!ct.IsCancellationRequested && _listener.IsListening)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync().ConfigureAwait(false);
                }
                catch (HttpListenerException)      { break; }
                catch (ObjectDisposedException)    { break; }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { AppLogger.Log($"[Web] Accept: {ex.Message}"); break; }

                _ = Task.Run(() => HandleRequest(ctx), ct);
            }
        }

        /// <summary>
        /// KORJAUS: lähettää SSE-kommenttipulssin (": keep-alive") 15 s välein.
        /// Tämä paljastaa katkenneet asiakkaat ja pitää välityspalvelimet tyytyväisinä.
        /// </summary>
        private async Task KeepAliveLoopAsync(CancellationToken ct)
        {
            byte[] beat = Encoding.UTF8.GetBytes(": keep-alive\n\n");
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);

                    HttpListenerResponse[] snapshot;
                    lock (_sseLock) snapshot = _sseClients.ToArray();

                    List<HttpListenerResponse> dead = null;
                    foreach (var resp in snapshot)
                    {
                        try { resp.OutputStream.Write(beat, 0, beat.Length); resp.OutputStream.Flush(); }
                        catch { (dead ??= new List<HttpListenerResponse>()).Add(resp); }
                    }
                    if (dead != null)
                    {
                        lock (_sseLock)
                            foreach (var d in dead) { _sseClients.Remove(d); try { d.Close(); } catch { } }
                    }
                }
            }
            catch (OperationCanceledException) { }
        }

        private void HandleRequest(HttpListenerContext ctx)
        {
            try
            {
                string path = ctx.Request.Url?.AbsolutePath ?? "/";
                switch (path)
                {
                    case "/api/events":      HandleSse(ctx);     break;
                    case "/api/data":        HandleJson(ctx);    break;
                    case "/metrics":         HandleMetrics(ctx); break;
                    // Staattiset tiedostot — CSS ja JS kirjoitetaan save-kansioon
                    // ja tarjoillaan selaimelle erikseen. Ilman näitä reittejä pyynöt
                    // ohjautuivat HandleHtml:ään joka palautti HTML:n CSS:n sijaan.
                    case "/wifi_report.css": HandleStaticFile(ctx, "wifi_report.css", "text/css"); break;
                    case "/wifi_report.js":  HandleStaticFile(ctx, "wifi_report.js",  "application/javascript"); break;
                    default:                 HandleHtml(ctx);    break;
                }
            }
            catch (Exception ex) { AppLogger.Log($"[Web] Request: {ex.Message}"); }
        }

        private void HandleStaticFile(HttpListenerContext ctx, string filename, string contentType)
        {
            string dir  = string.IsNullOrWhiteSpace(_cfg.SaveDirectory) ? "." : _cfg.SaveDirectory;
            string file = System.IO.Path.Combine(dir, filename);
            if (System.IO.File.Exists(file))
            {
                try
                {
                    byte[] bytes = System.IO.File.ReadAllBytes(file);
                    ctx.Response.ContentType                            = contentType + "; charset=utf-8";
                    ctx.Response.ContentLength64                        = bytes.Length;
                    ctx.Response.Headers["Cache-Control"]               = "no-cache";
                    ctx.Response.Headers["Access-Control-Allow-Origin"] = "*";
                    ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
                    ctx.Response.Close();
                    return;
                }
                catch (Exception ex) { AppLogger.Log($"[Web] Static {filename}: {ex.Message}"); }
            }
            // Tiedostoa ei löydy — 404
            ctx.Response.StatusCode = 404;
            WriteResponse(ctx, $"<!-- {filename} not found -->", "text/plain");
        }

        private void HandleSse(HttpListenerContext ctx)
        {
            ctx.Response.ContentType                            = "text/event-stream";
            ctx.Response.Headers["Cache-Control"]               = "no-cache";
            ctx.Response.Headers["Access-Control-Allow-Origin"] = "*";
            ctx.Response.Headers["X-Accel-Buffering"]           = "no";
            ctx.Response.SendChunked                            = true;

            // Lähetä alustava heartbeat-kommentti, jotta selain saa onopen-eventin.
            try
            {
                byte[] hello = Encoding.UTF8.GetBytes(": connected\n\n");
                ctx.Response.OutputStream.Write(hello, 0, hello.Length);
                ctx.Response.OutputStream.Flush();
            }
            catch { try { ctx.Response.Close(); } catch { } return; }

            // Lähetä viimeisin data heti yhdistyttäessä.
            var data = _lastData;
            if (data != null)
            {
                try
                {
                    byte[] buf = Encoding.UTF8.GetBytes($"data: {JsonSerializer.Serialize(data)}\n\n");
                    ctx.Response.OutputStream.Write(buf, 0, buf.Length);
                    ctx.Response.OutputStream.Flush();
                }
                catch { try { ctx.Response.Close(); } catch { } return; }
            }

            // Enimmäisasiakasrajoitus — suojelee palvelinta yhteysvuodolta
            lock (_sseLock)
            {
                if (_sseClients.Count >= MaxSseClients)
                {
                    ctx.Response.StatusCode = 503;
                    ctx.Response.Close();
                    AppLogger.Log($"[Web] SSE hylätty: max {MaxSseClients} asiakasta saavutettu");
                    return;
                }
                _sseClients.Add(ctx.Response);
            }
            // Yhteys jää auki — Push() ja KeepAliveLoop kirjoittavat siihen.
            // Asiakkaan katkaisu havaitaan kirjoitusvirheenä → Remove + Close.
        }

        private void HandleJson(HttpListenerContext ctx)
        {
            var data = _dataProvider?.Invoke() ?? _lastData;
            string json = data != null
                ? JsonSerializer.Serialize(data)
                : "{\"error\":\"ei dataa\"}";
            WriteResponse(ctx, json, "application/json");
        }

        private void HandleMetrics(HttpListenerContext ctx)
        {
            if (!_cfg.EnablePrometheusExport)
            {
                ctx.Response.StatusCode = 404;
                ctx.Response.Close();
                return;
            }
            var data = _lastData;
            string text = data != null
                ? ReportExporter.GetPrometheusMetrics(data.Networks, data.Speed)
                : "# no data\n";
            WriteResponse(ctx, text, "text/plain; version=0.0.4; charset=utf-8");
        }

        private void HandleHtml(HttpListenerContext ctx)
        {
            string dir  = string.IsNullOrWhiteSpace(_cfg.SaveDirectory) ? "." : _cfg.SaveDirectory;
            string file = System.IO.Path.Combine(dir, "wifi_report.html");

            if (System.IO.File.Exists(file))
            {
                try
                {
                    byte[] bytes = System.IO.File.ReadAllBytes(file);
                    ctx.Response.ContentType     = "text/html; charset=utf-8";
                    ctx.Response.ContentLength64 = bytes.Length;
                    ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
                    ctx.Response.Close();
                    return;
                }
                catch (Exception ex) { AppLogger.Log($"[Web] HTML read: {ex.Message}"); }
            }
            WriteResponse(ctx, BuildStatusPage(), "text/html; charset=utf-8");
        }

        private string BuildStatusPage()
        {
            var data = _lastData;
            return $@"<!DOCTYPE html><html lang='fi'><head><meta charset='UTF-8'>
<meta http-equiv='refresh' content='10'><title>Wi-Fi Analyzer</title>
<style>body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#0a0e1a;color:#e0e0e0;padding:20px}}
h1{{color:#10b981}}table{{border-collapse:collapse;width:100%}}
th{{background:#1a1a35;color:#3b82f6;padding:6px 8px;text-align:left}}
td{{padding:5px 8px;border-bottom:1px solid #1a1a2e}}</style></head><body>
<h1>📡 Wi-Fi Analyzer Pro — {DateTime.Now:HH:mm:ss}</h1>
<p style='color:#888;margin:8px 0 16px'>Sivu päivittyy 10 s välein. Täysi raportti: <a href='/' style='color:#3b82f6'>wifi_report.html</a></p>
{(data == null ? "<p>Ei dataa vielä...</p>" : BuildSimpleTable(data))}
</body></html>";
        }

        private static string BuildSimpleTable(DashboardData data)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"<p>AP-määrä: {data.Networks?.Count ?? 0} | Hälytykset: {data.AlertCount}</p>");
            sb.AppendLine("<table><tr><th>SSID</th><th>RSSI</th><th>CH</th><th>Band</th><th>Turva</th><th>Score</th></tr>");
            foreach (var ap in data.Networks ?? new List<AnalyzedAccessPoint>())
                sb.AppendLine($"<tr><td>{WebUtility.HtmlEncode(ap.Ssid)}</td><td>{ap.Rssi} dBm</td>" +
                              $"<td>{ap.Channel}</td><td>{ap.Band}</td>" +
                              $"<td>{WebUtility.HtmlEncode(ap.Security ?? "?")}</td><td>{ap.Score:F1}</td></tr>");
            sb.AppendLine("</table>");
            return sb.ToString();
        }

        private static void WriteResponse(HttpListenerContext ctx, string body, string ct)
        {
            byte[] buf = Encoding.UTF8.GetBytes(body);
            ctx.Response.ContentType                            = ct;
            ctx.Response.ContentLength64                        = buf.Length;
            ctx.Response.Headers["Access-Control-Allow-Origin"] = "*";
            ctx.Response.OutputStream.Write(buf, 0, buf.Length);
            ctx.Response.Close();
        }

        public void Stop()
        {
            try { _cts?.Cancel(); }      catch { }
            try { _listener?.Stop(); }   catch { }
            lock (_sseLock)
            {
                foreach (var r in _sseClients) try { r.Close(); } catch { }
                _sseClients.Clear();
            }
            try { _serveTask?.Wait(500); }     catch { }
            try { _keepAliveTask?.Wait(500); } catch { }
            Status = "Pysäytetty";
        }

        public void Dispose() { Stop(); _cts?.Dispose(); }
    }

    /// <summary>Tietorakenne dashboard-snapshottia varten.</summary>
    /// <summary>Tietorakenne dashboard-snapshottia varten.</summary>
    public class DashboardData
    {
        public DateTime                  Timestamp     { get; set; } = DateTime.Now;
        public List<AnalyzedAccessPoint> Networks      { get; set; }
        public int                       AlertCount    { get; set; }
        public SpeedSample               Speed         { get; set; }
        public string                    BestChannel   { get; set; }
        public string                    ScanStatus    { get; set; }
        public bool                      IsScanRunning { get; set; }
        public List<AlertEntry>          RecentAlerts  { get; set; }

        // ── Reaaliaikainen tietoturvadata ─────────────────────────
        /// <summary>Viimeisin 60 s deauth-tapahtumat aikajanaa varten (max 30).</summary>
        public List<DeauthEvent>         RecentDeauths     { get; set; }
        /// <summary>0=ei · 1=epäilty · 2=todennäköinen · 3=varmennettu (PMF).</summary>
        public int                       ActiveAttackLevel { get; set; }
        /// <summary>Lyhyt kuvaus aktiivisesta hyökkäyksestä bannerille.</summary>
        public string                    AttackSummary     { get; set; }
        /// <summary>Strukturoidut Evil Twin -havainnot (AP-taulukon korostus + paneeli).</summary>
        public List<EvilTwinAlert>       EvilTwinAlerts    { get; set; }
        /// <summary>Evil Twin -epäiltyjen BSSID:en lista AP-rivin värikorostusta varten.</summary>
        public List<string>              EvilTwinBssids    { get; set; }
        /// <summary>RTS/CTS per kanava — hidden node -indikaattori.</summary>
        public List<HiddenNodeStat>      HiddenNodeStats   { get; set; }

        // ── DPI: Liikennehavainnot avoimissa verkoissa ─────────────
        /// <summary>DNS-kyselyt ja TLS SNI -nimet (vain salaamattomat verkot).</summary>
        public List<TrafficObservation>  TrafficLog        { get; set; }

        // ── Uudet forensiikka- ja estopaneelit ─────────────────────
        /// <summary>Aktiivisten PCAP-nauhoitusten lukumäärä (0 = ei nauhoitusta).</summary>
        public int                       PcapActiveCount   { get; set; }
        /// <summary>Viimeisin PCAP-tiedostopolut (max 10).</summary>
        public List<string>              PcapRecentFiles   { get; set; }
        /// <summary>Reititimille lähetetyt MAC-esto-log-rivit (max 20).</summary>
        public List<string>              RouterBlockLog    { get; set; }
        /// <summary>EAPOL-kättelyaktiivisuus (PMKID-hyökkäysmalli).</summary>
        public List<EapolTracker.EapolSummaryEntry> EapolSummary { get; set; }
        /// <summary>Honeypot-havainnot (Probe Request -ansa).</summary>
        public List<HoneypotEvent>       HoneypotEvents    { get; set; }
        /// <summary>ThreatIntel-moottorin tilarivi (OTX/AbuseIPDB, tilastot).</summary>
        public string                    ThreatIntelStatus { get; set; }
        /// <summary>TI-löydökset: (Domain, ThreatLevel, Source) -tuplet.</summary>
        public List<(string Domain, string Level, string Source, DateTime Time)> ThreatIntelHits { get; set; }
    }
}
