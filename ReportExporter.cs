using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// JSON-, CSV- ja HTML-raporttien kirjoittaminen sekä vanhojen tiedostojen siivous.
    /// </summary>
    public class ReportExporter
    {
        private readonly WifiConfig _cfg;
        private DateTime _lastRecommendationWrite = DateTime.MinValue;

        private static readonly JsonSerializerOptions JsonWrite =
            new() { WriteIndented = true };

        // Kompakti serialisointi sivulle upotettavaan alkutilaan
        private static readonly JsonSerializerOptions JsonEmbed = new();

        public ReportExporter(WifiConfig cfg) => _cfg = cfg;

        // ── Päämetodi: tallenna kaikki raportit ───────────────────

        public string ExportAll(
            List<AnalyzedAccessPoint> aps,
            List<AlertEntry>          alerts,
            Dictionary<string, List<SignalPoint>> history,
            string bestChannel2G,
            string tag = null)
        {
            var now = DateTime.Now;
            string dir = ResolveSaveDir();
            try { Directory.CreateDirectory(dir); } catch { }

            var report = new WifiFullReport
            {
                Timestamp = now, BestChannel2G = bestChannel2G,
                Networks  = aps, History = history, Alerts = alerts
            };
            string json     = JsonSerializer.Serialize(report, JsonWrite);
            string fileName = tag != null
                ? $"wifi_{now:yyyyMMdd_HHmmss}_{tag}.json"
                : $"wifi_{now:yyyyMMdd_HHmm}.json";

            string stamped = Path.Combine(dir, fileName);
            string latest  = Path.Combine(dir, "wifi_data.json");
            WriteFileSafe(stamped, json);
            WriteFileSafe(latest,  json);

            PurgeOldReports(dir, "wifi_????????_????.json",
                TimeSpan.FromHours(_cfg.JsonRetentionHours));
            PurgeOldReports(dir, "wifi_????????_??????_*.json",
                TimeSpan.FromHours(_cfg.JsonRetentionHours));

            SaveCsv(aps, now, dir);
            SaveHtml(aps, alerts, now, dir, bestChannel2G);
            WriteRecommendationIfNeeded(aps, bestChannel2G, dir);

            if (_cfg.EnablePrometheusExport)
            {
                ExportPrometheusAlertRules(dir);
                ExportGrafanaDashboard(dir);
            }

            return $"✓ Viety: {Path.GetFileName(stamped)}, wifi_data.csv, wifi_report.html" +
                   (_cfg.EnablePrometheusExport ? ", alert_rules.yml, grafana_dashboard.json" : "");
        }

        // ── CSV ───────────────────────────────────────────────────

        private static void SaveCsv(
            List<AnalyzedAccessPoint> aps, DateTime now, string dir)
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("Timestamp,BSSID,SSID,RSSI,Grade,Channel,Band,Security," +
                              "CoChannel,Adjacent,Jitter,Stability,TrafficKB,Score,Vendor,MeshNote,ChUtil%");
                foreach (var ap in aps)
                    sb.AppendLine(string.Format(
                        "{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10:F1},{11},{12},{13:F1},{14},{15},{16}",
                        now.ToString("yyyy-MM-dd HH:mm:ss"),
                        ap.Bssid, CsvHelper.Escape(ap.Ssid), ap.Rssi, ap.Grade,
                        ap.Channel, ap.Band, CsvHelper.Escape(ap.Security ?? ""),
                        ap.CoChannelCount, ap.AdjacentOverlapCount,
                        ap.SignalJitter, ap.StabilityTag, ap.TrafficBytes / 1024,
                        ap.Score, CsvHelper.Escape(ap.Vendor ?? ""),
                        CsvHelper.Escape(ap.MeshNote ?? ""),
                        ap.ChannelUtilization.HasValue ? ap.ChannelUtilization.Value.ToString() : ""));
                WriteFileSafe(Path.Combine(dir, "wifi_data.csv"), sb.ToString());
            }
            catch (Exception ex) { AppLogger.Log($"[CSV] {ex.Message}"); }
        }

        // ── HTML (live SSE-dashboard) ─────────────────────────────

        private static void SaveHtml(
            List<AnalyzedAccessPoint> aps,
            List<AlertEntry>          alerts,
            DateTime now, string dir, string bestCh)
        {
            // KORJAUS: Erilliset try-catch per tiedosto — aiemmin yhdessä lohkossa oleva
            // kirjoitusvirhe (esim. oikeuspuute css-tiedostolla) esti kaikkien tiedostojen
            // kirjoittamisen. Nyt kukin epäonnistuminen kirjataan erikseen.
            try { WriteFileSafe(Path.Combine(dir, "wifi_report.css"), GetDashboardCss()); }
            catch (Exception ex) { AppLogger.Log($"[HTML] CSS: {ex.Message}"); }

            try { WriteFileSafe(Path.Combine(dir, "wifi_report.js"), GetDashboardJs()); }
            catch (Exception ex) { AppLogger.Log($"[HTML] JS: {ex.Message}"); }

            try { WriteFileSafe(Path.Combine(dir, "wifi_report.html"), BuildHtml(aps, alerts, now, bestCh)); }
            catch (Exception ex) { AppLogger.Log($"[HTML] HTML: {ex.Message}"); }
        }

        private static string BuildHtml(
            List<AnalyzedAccessPoint> aps,
            List<AlertEntry>          alerts,
            DateTime now, string bestCh)
        {
            var initial = new DashboardData
            {
                Timestamp     = now,
                Networks      = aps,
                AlertCount    = alerts?.Count ?? 0,
                BestChannel   = bestCh,
                Speed         = null,
                ScanStatus    = "",
                IsScanRunning = false,
                RecentAlerts  = (alerts ?? new List<AlertEntry>())
                    .Skip(Math.Max(0, (alerts?.Count ?? 0) - 15)).ToList()
            };
            string initialJson = JsonSerializer.Serialize(initial, JsonEmbed)
                .Replace("<", "\\u003c").Replace(">", "\\u003e");
            string alertsJson = JsonSerializer.Serialize(
                (alerts ?? new List<AlertEntry>())
                    .OrderByDescending(a => a.Time).Take(50).ToList(), JsonEmbed)
                .Replace("<", "\\u003c").Replace(">", "\\u003e");

            var sb = new StringBuilder(8192);
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang='fi'><head><meta charset='UTF-8'>");
            sb.AppendLine("<meta name='viewport' content='width=device-width,initial-scale=1'>");
            sb.AppendLine("<title>Wi-Fi Analyzer Pro</title>");
            // Ulkoiset tiedostot — ei inline CSS/JS-stringejä C#:ssa
            sb.AppendLine("<link rel='stylesheet' href='wifi_report.css'>");
            sb.AppendLine("<script src='https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js'></script>");
            sb.AppendLine("</head><body>");

            // Header
            sb.AppendLine("<header>");
            sb.AppendLine("  <div class='brand'><span class='logo'>&#128225;</span><div>");
            sb.AppendLine("    <h1>Wi-Fi Analyzer Pro</h1>");
            sb.AppendLine($"    <div class='ts'>P&auml;ivitetty <span id='ts'>{now:dd.MM.yyyy HH:mm:ss}</span>");
            sb.AppendLine($"     &middot; Paras 2.4 GHz: <span id='best-ch' class='accent'>{HE(bestCh ?? "?")}</span></div>");
            sb.AppendLine("  </div></div>");
            sb.AppendLine("  <div class='header-right'>");
            sb.AppendLine("    <div class='scan-pill' id='scan-pill'>");
            sb.AppendLine("      <span class='scan-dot' id='scan-dot'></span>");
            sb.AppendLine("      <span id='scan-label'>Odottaa...</span>");
            sb.AppendLine("    </div>");
            sb.AppendLine("    <input id='filter' class='filter-box' placeholder='Suodata SSID...' />");
            sb.AppendLine("    <span id='conn-dot' class='conn-dot offline'></span>");
            sb.AppendLine("    <span id='conn-label' class='muted small'>Yhdist&auml;&auml;...</span>");
            sb.AppendLine("    <a href='/api/data' target='_blank' class='link-btn'>JSON</a>");
            sb.AppendLine("    <a href='wifi_data.csv' target='_blank' class='link-btn'>CSV</a>");
            sb.AppendLine("    <a href='/metrics' target='_blank' class='link-btn'>Metrics</a>");
            sb.AppendLine("  </div>");
            sb.AppendLine("</header>");

            // Stat-kortit
            sb.AppendLine("<section class='stats'>");
            sb.AppendLine("  <div class='stat'><div class='stat-n' id='s-total'>0</div><div class='stat-l'>Verkot</div></div>");
            sb.AppendLine("  <div class='stat'><div class='stat-n success' id='s-wpa3'>0</div><div class='stat-l'>WPA3</div></div>");
            sb.AppendLine("  <div class='stat'><div class='stat-n error' id='s-open'>0</div><div class='stat-l'>Avoimet</div></div>");
            sb.AppendLine("  <div class='stat'><div class='stat-n warn' id='s-alerts'>0</div><div class='stat-l'>H&auml;lytykset</div></div>");
            sb.AppendLine("  <div class='stat'><div class='stat-n' id='s-ping'>&mdash;</div><div class='stat-l'>Ping ms</div></div>");
            sb.AppendLine("  <div class='stat'><div class='stat-n accent' id='s-dl'>&mdash;</div><div class='stat-l'>DL KB/s</div></div>");
            sb.AppendLine("</section>");

            // Kaaviot
            sb.AppendLine("<section class='charts-grid'>");
            sb.AppendLine("  <div class='card'><h2>Signaalivahvuus (RSSI)</h2><canvas id='c-rssi'></canvas></div>");
            sb.AppendLine("  <div class='card'><h2>Kanavakuorma</h2><canvas id='c-ch'></canvas></div>");
            sb.AppendLine("  <div class='card'><h2>Tietoturvajakauma</h2><canvas id='c-sec'></canvas></div>");
            sb.AppendLine("  <div class='card'><h2>Top-10 pisteytys</h2><canvas id='c-score'></canvas></div>");
            sb.AppendLine("</section>");

            // DPI-analytiikka (piirakkakaavio + aikajana)
            sb.AppendLine("<section class='charts-grid dpi-analytics'>");
            sb.AppendLine("  <div class='card'>");
            sb.AppendLine("    <h2>Top Palvelut <span class='muted small' id='svc-obs-count'></span></h2>");
            sb.AppendLine("    <canvas id='c-services' height='210'></canvas>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div class='card' style='grid-column: span 3'>");
            sb.AppendLine("    <h2>Verkkoaktiivisuus — 60 s aikajana <span class='muted small'>(DPI-havainnot 5 s jaksoissa)</span></h2>");
            sb.AppendLine("    <canvas id='c-activity' height='120'></canvas>");
            sb.AppendLine("  </div>");
            sb.AppendLine("</section>");

            // AP-taulukko
            sb.AppendLine("<section class='card table-card'>");
            sb.AppendLine("  <div class='table-toolbar'>");
            sb.AppendLine("    <h2>Havaitut verkot <span id='net-count' class='muted'></span></h2>");
            sb.AppendLine("    <div class='sort-hint muted small'>Klikkaa sarakeotsikkoa lajitellaksesi</div>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div class='table-wrap'><table id='net-table'>");
            sb.AppendLine("    <thead><tr>");
            sb.AppendLine("      <th data-col='Ssid'>SSID</th>");
            sb.AppendLine("      <th data-col='Rssi' class='sdesc'>RSSI</th>");
            sb.AppendLine("      <th data-col='_bar' class='nosort'>Signaali</th>");
            sb.AppendLine("      <th data-col='_spark' class='nosort'>Historia</th>");
            sb.AppendLine("      <th data-col='Channel'>CH</th>");
            sb.AppendLine("      <th data-col='Band'>Band</th>");
            sb.AppendLine("      <th data-col='Security'>Turva</th>");
            sb.AppendLine("      <th data-col='_int'>INT</th>");
            sb.AppendLine("      <th data-col='ChannelUtilization'>Util%</th>");
            sb.AppendLine("      <th data-col='SignalJitter'>Jitter</th>");
            sb.AppendLine("      <th data-col='Score'>Score</th>");
            sb.AppendLine("      <th data-col='SignalTrend'>Trendi</th>");
            sb.AppendLine("      <th data-col='Vendor'>Vendor</th>");
            sb.AppendLine("    </tr></thead><tbody id='ap-tbody'></tbody>");
            sb.AppendLine("  </table></div>");
            sb.AppendLine("</section>");

            // Hälytykset
            sb.AppendLine("<section id='alerts-section' class='card alerts-card' hidden>");
            sb.AppendLine("  <h2>&#9888; H&auml;lytykset <span id='alert-badge'></span></h2>");
            sb.AppendLine("  <div id='alert-list'></div>");
            sb.AppendLine("</section>");

            // ── Hyökkäysbanneri (piilotettu kun level=0) ──────────────
            sb.AppendLine("<div id='attack-banner' class='attack-banner hidden'>");
            sb.AppendLine("  <div class='attack-icon' id='attack-icon'>&#9888;</div>");
            sb.AppendLine("  <div class='attack-body'>");
            sb.AppendLine("    <div class='attack-title' id='attack-title'>Aktiivinen hyökkäys</div>");
            sb.AppendLine("    <div class='attack-msg' id='attack-msg'></div>");
            sb.AppendLine("  </div>");
            sb.AppendLine("  <div class='attack-level-badge' id='attack-level-badge'></div>");
            sb.AppendLine("</div>");

            // ── Tietoturvapaneeli (3 kolumnia) ────────────────────────
            sb.AppendLine("<section class='security-grid'>");

            // Deauth-aikajana
            sb.AppendLine("  <div class='card sec-card' id='deauth-card'>");
            sb.AppendLine("    <h2>Deauth-valvonta");
            sb.AppendLine("      <span id='deauth-count-badge' class='sec-badge'></span>");
            sb.AppendLine("    </h2>");
            sb.AppendLine("    <div class='deauth-timeline' id='deauth-timeline'>");
            sb.AppendLine("      <canvas id='c-deauth' height='70'></canvas>");
            sb.AppendLine("    </div>");
            sb.AppendLine("    <div id='deauth-list' class='sec-list'></div>");
            sb.AppendLine("  </div>");

            // Evil Twin -paneeli
            sb.AppendLine("  <div class='card sec-card' id='eviltwin-card'>");
            sb.AppendLine("    <h2>Evil Twin -havainnot");
            sb.AppendLine("      <span id='et-count-badge' class='sec-badge error'></span>");
            sb.AppendLine("    </h2>");
            sb.AppendLine("    <div id='eviltwin-list' class='sec-list'></div>");
            sb.AppendLine("  </div>");

            // DPI — liikennehavainnot
            sb.AppendLine("  <div class='card sec-card' id='dpi-card'>");
            sb.AppendLine("    <h2>Liikennehavainnot <span class='muted small'>(avoimet verkot)</span></h2>");
            sb.AppendLine("    <div id='dpi-list' class='sec-list'></div>");
            sb.AppendLine("    <div class='muted small' style='margin-top:8px'>DNS-kyselyt &amp; TLS SNI</div>");
            sb.AppendLine("  </div>");

            // PCAP-nauhoitukset
            sb.AppendLine("  <div class='card sec-card' id='pcap-card'>");
            sb.AppendLine("    <h2><span id='pcap-dot' class='pcap-dot-off'></span>PCAP-nauhoitukset <span id='pcap-active-badge' class='sec-badge error'></span></h2>");
            sb.AppendLine("    <div id='pcap-active-row' class='pcap-active-row hidden'><span class='pcap-rec-label'>&#9679; NAUHOITTAA</span></div>");
            sb.AppendLine("    <div id='pcap-list' class='sec-list'></div>");
            sb.AppendLine("    <div class='muted small' style='margin-top:6px'>Wireshark &mdash; linkkityyppi 127 (802.11+radiotap)</div>");
            sb.AppendLine("  </div>");

            // Reititinblokkaukset
            sb.AppendLine("  <div class='card sec-card' id='router-card'>");
            sb.AppendLine("    <h2>Reititin-esto <span id='router-badge' class='sec-badge'></span></h2>");
            sb.AppendLine("    <div class='muted small' style='margin-bottom:5px'>Unifi &middot; pfSense &middot; OPNsense</div>");
            sb.AppendLine("    <div id='router-list' class='sec-list'></div>");
            sb.AppendLine("  </div>");

            // EAPOL / Handshake
            sb.AppendLine("  <div class='card sec-card' id='eapol-card'>");
            sb.AppendLine("    <h2>EAPOL / Handshake <span id='eapol-badge' class='sec-badge'></span></h2>");
            sb.AppendLine("    <div class='muted small' style='margin-bottom:5px'>PMKID-keräilymalli &mdash; yli 3 AP / 60 s</div>");
            sb.AppendLine("    <div id='eapol-list' class='sec-list'></div>");
            sb.AppendLine("    <div id='eapol-status' class='muted small' style='margin-top:5px'></div>");
            sb.AppendLine("  </div>");

            // Honeypot
            sb.AppendLine("  <div class='card sec-card' id='honeypot-card'>");
            sb.AppendLine("    <h2>Honeypot-ansa <span id='honeypot-badge' class='sec-badge error'></span></h2>");
            sb.AppendLine("    <div class='muted small' style='margin-bottom:5px'>Probe Request &rarr; decoy-SSID</div>");
            sb.AppendLine("    <div id='honeypot-list' class='sec-list'></div>");
            sb.AppendLine("  </div>");

            sb.AppendLine("  <div class='card sec-card' id='ti-card'>");
            sb.AppendLine("    <h2>Uhkatiedustelu <span id='ti-badge' class='sec-badge'></span></h2>");
            sb.AppendLine("    <div id='ti-status' class='muted small' style='margin-bottom:5px'></div>");
            sb.AppendLine("    <div id='ti-list' class='sec-list'></div>");
            sb.AppendLine("  </div>");

            sb.AppendLine("</section>");

            sb.AppendLine("<div id='toasts'></div>");

            sb.AppendLine("<footer class='muted small'>");
            sb.AppendLine("  A&ge;-50 &middot; B&ge;-60 &middot; C&ge;-70 &middot; D&ge;-80 &middot; F&lt;-80 dBm &nbsp;|&nbsp;");
            sb.AppendLine("  WPA3=&#128274; WPA2=&#128273; WPA=&#9888; Open=&#10060; &nbsp;|&nbsp; P&auml;ivittyy SSE-streamill&auml; automaattisesti");
            sb.AppendLine("</footer>");

            // Alkudata upotettuna JSON-muodossa — JavaScript lukee nämä käynnistyessä
            sb.AppendLine("<script id='__initial' type='application/json'>");
            sb.AppendLine(initialJson);
            sb.AppendLine("</script>");
            sb.AppendLine("<script id='__alerts' type='application/json'>");
            sb.AppendLine(alertsJson);
            sb.AppendLine("</script>");

            // JS ulkoisena tiedostona — kaikki escaping-ongelmat poistuvat
            sb.AppendLine("<script src='wifi_report.js'></script>");
            sb.AppendLine("</body></html>");
            return sb.ToString();
        }

        /// <summary>
        /// Palauttaa CSS-sisällön wifi_report.css-tiedostoon kirjoitettavaksi.
        /// Pidetään erillisessä metodissa, jotta HTML-tiedostossa ei tarvita
        /// inline-&lt;style&gt;-blokkia eikä C#-escaping-ongelmia CSS:n kanssa.
        /// </summary>
        private static string GetDashboardCss()
        {
            var sb = new StringBuilder(8192);
            sb.Append(@"
:root{
  --bg:#0a0e1a;--card:#131826;--border:#1e2840;
  --text:#e5e7eb;--muted:#6b7280;--muted2:#374151;
  --accent:#3b82f6;--success:#10b981;--warn:#f59e0b;--error:#ef4444;
  --grade-a:#10b981;--grade-b:#3b82f6;--grade-c:#f59e0b;--grade-d:#f97316;--grade-f:#ef4444;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:var(--bg);color:var(--text);min-height:100vh}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,system-ui,sans-serif;
     padding:20px 24px;line-height:1.5;font-size:14px}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;
       margin-bottom:20px;background:var(--card);border:1px solid var(--border);
       border-radius:12px;padding:14px 20px}
.brand{display:flex;align-items:center;gap:14px}
.logo{font-size:1.8em;line-height:1}
h1{font-size:1.25em;font-weight:700;color:var(--text)}
.ts{color:var(--muted);font-size:.82em;margin-top:2px}
.ts .accent{color:var(--accent);font-weight:600}
.header-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.scan-pill{display:flex;align-items:center;gap:6px;padding:4px 10px;border-radius:20px;
           background:var(--muted2);font-size:.8em;transition:background .3s}
.scan-pill.running{background:#1e3a5f}
.scan-dot{width:8px;height:8px;border-radius:50%;background:var(--muted);transition:background .3s}
.scan-dot.running{background:var(--accent);animation:pdot 1s ease-in-out infinite}
@keyframes pdot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
.conn-dot{width:9px;height:9px;border-radius:50%;display:inline-block;transition:all .3s}
.conn-dot.live{background:var(--success);box-shadow:0 0 8px var(--success);animation:plive 2s ease-in-out infinite}
.conn-dot.offline{background:var(--error)}
.conn-dot.connecting{background:var(--warn)}
@keyframes plive{0%,100%{opacity:1}50%{opacity:.5}}
.filter-box{background:var(--muted2);border:1px solid var(--border);color:var(--text);
            border-radius:8px;padding:5px 10px;font-size:.85em;width:170px;outline:none;transition:border-color .2s}
.filter-box:focus{border-color:var(--accent)}
.link-btn{color:var(--accent);text-decoration:none;padding:4px 8px;border:1px solid var(--border);
          border-radius:6px;font-size:.8em;transition:all .15s;white-space:nowrap}
.link-btn:hover{background:var(--accent);color:#fff}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 10px;text-align:center}
.stat-n{font-size:1.8em;font-weight:700;color:var(--accent);transition:color .3s;line-height:1.1}
.stat-n.success{color:var(--success)}.stat-n.warn{color:var(--warn)}.stat-n.error{color:var(--error)}
.stat-l{font-size:.72em;color:var(--muted);margin-top:4px;text-transform:uppercase;letter-spacing:.05em}
.charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;margin-bottom:14px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;margin-bottom:12px}
.card h2{font-size:.78em;color:var(--muted);margin-bottom:12px;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
canvas{max-height:220px}
.table-toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.82em}
thead th{background:#0f1929;color:var(--accent);padding:8px 10px;text-align:left;font-weight:600;
         position:sticky;top:0;border-bottom:2px solid var(--border);
         cursor:pointer;user-select:none;white-space:nowrap;transition:background .15s}
thead th:hover:not(.nosort){background:#1a2845}
thead th.sasc::after{content:' \2191';color:var(--warn)}
thead th.sdesc::after{content:' \2193';color:var(--warn)}
thead th.nosort{cursor:default}
tbody tr{transition:background .15s}
tbody tr:hover td{background:#151f35}
tbody tr.flash td{animation:rflash .5s ease-out}
@keyframes rflash{0%{background:#1e3a5f}100%{background:transparent}}
tbody tr.conn-row td:first-child{border-left:3px solid var(--success)}
td{padding:6px 10px;border-bottom:1px solid #111827;vertical-align:middle}
td.mono{font-family:'SF Mono',Menlo,Consolas,monospace;font-size:.8em;color:var(--muted)}
.grade-A{color:var(--grade-a);font-weight:700}.grade-B{color:var(--grade-b);font-weight:700}
.grade-C{color:var(--grade-c);font-weight:700}.grade-D{color:var(--grade-d);font-weight:700}
.grade-F{color:var(--grade-f);font-weight:700}
.sec-wpa3{color:var(--success);font-weight:600}.sec-wpa2{color:var(--accent)}
.sec-wpa{color:var(--warn)}.sec-open{color:var(--error);font-weight:700}
.rssi-wrap{width:80px;background:#1a2235;border-radius:4px;height:8px;overflow:hidden}
.rssi-bar{height:100%;border-radius:4px;transition:width .6s ease,background-color .6s ease}
canvas.spark{display:block}
.alerts-card{border-left:4px solid var(--error)}
.alert-row{background:#140d10;border-left:3px solid var(--error);
           padding:7px 12px;margin:5px 0;border-radius:6px;font-size:.82em;display:flex;gap:8px;align-items:baseline}
.alert-row.tEvilTwin{border-color:#dc2626}.alert-row.tWeakSignal{border-color:var(--warn)}
.alert-row.tNewAP{border-color:var(--success)}.alert-row.tRoaming{border-color:var(--accent)}
.alert-ts{color:var(--muted);font-size:.8em;white-space:nowrap}
.alert-type{font-weight:700;color:#fca5a5;min-width:90px}
#toasts{position:fixed;bottom:20px;right:20px;display:flex;flex-direction:column;gap:8px;z-index:1000;pointer-events:none}
.toast{background:#1e2840;border:1px solid var(--border);border-radius:10px;padding:12px 16px;
       max-width:300px;font-size:.82em;pointer-events:auto;
       animation:tin .25s ease-out;box-shadow:0 8px 24px rgba(0,0,0,.5)}
.toast.tout{animation:tout .25s ease-in forwards}
@keyframes tin{from{transform:translateX(120%);opacity:0}to{transform:none;opacity:1}}
@keyframes tout{from{transform:none;opacity:1}to{transform:translateX(120%);opacity:0}}
.toast-hd{font-weight:700;color:var(--warn);margin-bottom:2px}
.toast.tevil .toast-hd{color:var(--error)}.toast.tok .toast-hd{color:var(--success)}
.muted{color:var(--muted)}.small{font-size:.8em}.accent{color:var(--accent)}
footer{margin-top:20px;text-align:center;padding-top:14px;border-top:1px solid var(--border);
       color:var(--muted);font-size:.78em}
@media(max-width:700px){header{flex-direction:column;align-items:flex-start}
.header-right{width:100%}.filter-box{width:100%}body{padding:12px}}
/* ── Hyökkäysbanneri ─────────────────────────────────────────── */
.attack-banner{display:flex;align-items:center;gap:16px;padding:14px 20px;
  border-radius:10px;margin-bottom:14px;border:2px solid var(--error);
  background:#1a0a0a;transition:all .3s}
.attack-banner.hidden{display:none}
.attack-banner.lvl1{border-color:var(--warn);background:#1a1400}
.attack-banner.lvl2{border-color:#f97316;background:#1a0d00}
.attack-banner.lvl3{border-color:var(--error);background:#1a0000;
  animation:blink-border 1s ease-in-out infinite}
@keyframes blink-border{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0)}
  50%{box-shadow:0 0 0 6px rgba(239,68,68,.3)}}
.attack-icon{font-size:2em;flex-shrink:0}
.attack-body{flex:1}
.attack-title{font-weight:700;font-size:.95em;margin-bottom:4px}
.attack-title.lvl3{color:var(--error)}
.attack-title.lvl2{color:#f97316}
.attack-title.lvl1{color:var(--warn)}
.attack-msg{font-size:.8em;color:var(--muted)}
.attack-level-badge{padding:4px 10px;border-radius:20px;font-size:.78em;font-weight:700;flex-shrink:0}
.badge-lvl3{background:#7f1d1d;color:#fca5a5}
.badge-lvl2{background:#7c2d12;color:#fed7aa}
.badge-lvl1{background:#78350f;color:#fde68a}
/* ── Tietoturvagrid ──────────────────────────────────────────── */
.security-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-bottom:14px}
.sec-card{min-height:180px}
.sec-badge{display:inline-block;padding:1px 7px;border-radius:10px;font-size:.72em;
  font-weight:700;background:var(--muted2);color:var(--text);margin-left:6px;vertical-align:middle}
.sec-badge.error{background:#7f1d1d;color:#fca5a5}
.sec-list{max-height:200px;overflow-y:auto;font-size:.8em}
.sec-row{padding:5px 0;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:baseline}
.sec-row:last-child{border-bottom:0}
.sec-ts{color:var(--muted);font-size:.78em;white-space:nowrap;min-width:52px}
.sec-lbl{font-weight:600;min-width:60px}
.sec-lbl.dns{color:#60a5fa}.sec-lbl.sni{color:#34d399}.sec-lbl.deauth{color:var(--warn)}
.sec-lbl.broadcast{color:var(--error);font-size:.85em}
.sec-detail{color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* Evil Twin AP-rivikorostus */
tbody tr.evil-twin-row td{background:#1f0a0a}
tbody tr.evil-twin-row td:first-child{border-left:3px solid var(--error)}
.et-conf-3{color:var(--error);font-weight:700}
.et-conf-2{color:#f97316;font-weight:600}
.et-conf-1{color:var(--warn)}
/* Deauth-pylväskaavio */
#c-deauth{width:100%;display:block}
/* Blacklist-rivi DPI-paneelissa */
.bl-row{background:#1a0800!important;border-left:3px solid var(--error)}
/* ── PCAP-nauhoituspaneeli ─────────────────────────────────── */
.pcap-dot-off{display:inline-block;width:10px;height:10px;border-radius:50%;
  background:var(--muted2);margin-right:7px;vertical-align:middle;transition:background .3s}
.pcap-dot-on{display:inline-block;width:10px;height:10px;border-radius:50%;
  background:var(--error);margin-right:7px;vertical-align:middle;
  animation:pcap-pulse 1s ease-in-out infinite}
@keyframes pcap-pulse{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,.6);opacity:1}
  50%{box-shadow:0 0 0 6px rgba(239,68,68,0);opacity:.8}}
.pcap-active-row{padding:6px 10px;border-radius:6px;background:#2d0a0a;
  border:1px solid var(--error);margin-bottom:8px}
.pcap-rec-label{color:var(--error);font-weight:700;font-size:.85em;
  animation:pcap-pulse 1s ease-in-out infinite}
.hidden{display:none}
/* ── Reititinblokkaus ──────────────────────────────────────── */
.router-row-new{animation:flash-blue .8s ease-out}
/* ── EAPOL ─────────────────────────────────────────────────── */
.eapol-suspicious{color:var(--error);font-weight:700}
.eapol-normal{color:var(--muted)}
/* ── Honeypot ──────────────────────────────────────────────── */
.honeypot-row{border-left:3px solid #8b5cf6}
.honeypot-row .sec-lbl{color:#8b5cf6}
");
            return sb.ToString();
        }

        /// <summary>
        /// Palauttaa JavaScript-sisällön wifi_report.js-tiedostoon kirjoitettavaksi.
        /// Erillinen tiedosto eliminoi kaksi C#-kompilointiongelmaa:
        ///   1) 'var ge = function' -alias aiheuttaisi CS1056 verbatim-stringin ulkopuolella
        ///   2) JavaScript-emojien surrogaattiparit (JavaScript-syntaksi 0xD83D+0xDEA8 jne.)
        ///      eivat kelpaa C#-kaantajalle edes verbatim-merkkijonoissa, silla kaantaja
        ///      kasittelee kaikki '\uXXXX'-sekvenssit leksertasolla ennen tokenisointia.
        /// Ratkaisu: kaikki emoji korvataan BMP-merkeillä tai tavallisilla Unicode-arvoilla.
        /// </summary>
        private static string GetDashboardJs()
        {
            var sb = new StringBuilder(16384);
            sb.Append(@"
(function(){
'use strict';
var ge=function(id){return document.getElementById(id);};
var enc=function(s){return(s||'').replace(/[&<>]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;'}[c];});};

var state=JSON.parse(ge('__initial').textContent);
var alerts=JSON.parse(ge('__alerts').textContent);

var hist={};var HMAX=40;
function pushH(bssid,rssi){
  if(!hist[bssid])hist[bssid]=[];
  hist[bssid].push({t:Date.now(),v:rssi});
  if(hist[bssid].length>HMAX)hist[bssid].shift();
}
(state.Networks||[]).forEach(function(a){pushH(a.Bssid,a.Rssi);});

Chart.defaults.color='#9ca3af';
Chart.defaults.borderColor='#1e2840';
Chart.defaults.font.family='system-ui,sans-serif';
Chart.defaults.font.size=11;

function rssiCol(r){return r>=-50?'#10b981':r>=-60?'#3b82f6':r>=-70?'#f59e0b':r>=-80?'#f97316':'#ef4444';}
function barPct(r){return Math.max(2,Math.min(100,Math.round((r+100)/70*100)));}
function secCls(s){return/3/.test(s)?'sec-wpa3':/Ent/.test(s)?'sec-wpa2':/2/.test(s)?'sec-wpa2':s==='WPA'?'sec-wpa':s==='Open'?'sec-open':'';}
function secCol(s){return/3/.test(s)?'#10b981':/2/.test(s)?'#3b82f6':s==='WPA'?'#f59e0b':s==='Open'?'#ef4444':'#6b7280';}

var AN={duration:400,easing:'easeOutQuart'};
var C={};
function buildCharts(){
  C.rssi=new Chart(ge('c-rssi'),{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:[],borderRadius:5,borderWidth:0}]},options:{plugins:{legend:{display:false}},animation:AN,scales:{y:{min:-100,max:-20,title:{display:true,text:'dBm'}}}}});
  C.ch=new Chart(ge('c-ch'),{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#3b82f6',borderRadius:5,borderWidth:0}]},options:{plugins:{legend:{display:false}},animation:AN,scales:{y:{ticks:{stepSize:1}}}}});
  C.sec=new Chart(ge('c-sec'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:[],borderWidth:2,borderColor:'#131826'}]},options:{plugins:{legend:{position:'bottom'}},animation:AN}});
  C.score=new Chart(ge('c-score'),{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#3b82f6',borderRadius:5,borderWidth:0}]},options:{indexAxis:'y',plugins:{legend:{display:false}},animation:AN}});

  // ── DPI-analytiikka: Top Palvelut -piirakka ──────────────────
  C.services=new Chart(ge('c-services'),{
    type:'doughnut',
    data:{labels:[],datasets:[{data:[],backgroundColor:[
      '#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6',
      '#06b6d4','#f97316','#84cc16','#ec4899','#6b7280'
    ],borderWidth:2,borderColor:'#131826'}]},
    options:{
      plugins:{legend:{position:'right',labels:{font:{size:10},color:'#9ca3af',boxWidth:12}}},
      animation:{duration:400}
    }
  });

  // ── DPI-analytiikka: Verkkoaktiivisuus aikajana ──────────────
  // 12 x 5 s = 60 s, pinottu kaaviotyyppi palvelukohtaisesti
  C.activity=new Chart(ge('c-activity'),{
    type:'bar',
    data:{labels:['-55','-50','-45','-40','-35','-30','-25','-20','-15','-10','-5','0'],datasets:[]},
    options:{
      plugins:{legend:{position:'bottom',labels:{font:{size:9},color:'#9ca3af',boxWidth:10}}},
      animation:{duration:200},
      scales:{
        x:{stacked:true,ticks:{font:{size:9},color:'#6b7280'}},
        y:{stacked:true,min:0,ticks:{stepSize:1,font:{size:9},color:'#6b7280'}}
      }
    }
  });
}

// ── DPI-analytiikkakaavioiden päivitys ────────────────────────
var SVC_COLORS=['#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6','#06b6d4','#f97316','#84cc16','#ec4899','#6b7280'];

function updateAnalyticsCharts(){
  var obs=window._dpiObs||[];
  if(!C.services||!C.activity) return;

  // Piirakka: laske palvelukohtaiset esiintymät
  var counts={};
  obs.forEach(function(o){
    var k=o.ServiceName||'Tuntematon';
    counts[k]=(counts[k]||0)+1;
  });
  // Järjestä laskevasti, max 9 + 'Muut'
  var entries=Object.keys(counts).map(function(k){return{k:k,v:counts[k]};})
    .sort(function(a,b){return b.v-a.v;});
  var top=entries.slice(0,9), rest=entries.slice(9);
  var labels=top.map(function(e){return e.k;}), data=top.map(function(e){return e.v;});
  if(rest.length>0){
    labels.push('Muut ('+rest.length+')');
    data.push(rest.reduce(function(s,e){return s+e.v;},0));
  }
  C.services.data.labels=labels;
  C.services.data.datasets[0].data=data;
  C.services.update('none');
  var total=obs.length;
  if(ge('svc-obs-count'))ge('svc-obs-count').textContent='('+total+' havaintoa)';

  // Aikajana: 12 x 5 s pinottu per palvelu (max 5 palvelua + Muut)
  var now=Date.now();
  var topSvcs=entries.slice(0,5).map(function(e){return e.k;});
  var buckets={};
  topSvcs.concat(['Muut']).forEach(function(k){buckets[k]=new Array(12).fill(0);});

  obs.forEach(function(o){
    var age=now-new Date(o.LastSeen).getTime();
    var bi=Math.floor(age/5000);
    if(bi<0||bi>=12)return;
    var svc=o.ServiceName||'Tuntematon';
    var key=topSvcs.indexOf(svc)>=0?svc:'Muut';
    buckets[key][11-bi]++;
  });

  var datasets=topSvcs.map(function(svc,idx){return{
    label:svc,
    data:buckets[svc],
    backgroundColor:SVC_COLORS[idx]||'#6b7280',
    borderWidth:0,borderRadius:2
  };});
  // Lisää 'Muut' vain jos sillä on dataa
  if(buckets['Muut'].some(function(v){return v>0;}))
    datasets.push({label:'Muut',data:buckets['Muut'],backgroundColor:'#6b7280',borderWidth:0,borderRadius:2});

  C.activity.data.datasets=datasets;
  C.activity.update('none');
}

var sortCol='Rssi',sortAsc=false,filterStr='';
document.querySelectorAll('thead th[data-col]').forEach(function(th){
  if(th.classList.contains('nosort'))return;
  th.addEventListener('click',function(){
    var col=th.dataset.col;
    if(sortCol===col)sortAsc=!sortAsc;
    else{sortCol=col;sortAsc=(col==='Ssid'||col==='Vendor');}
    document.querySelectorAll('thead th').forEach(function(t){t.classList.remove('sasc','sdesc');});
    th.classList.add(sortAsc?'sasc':'sdesc');
    renderTable(state.Networks||[]);
  });
});
ge('filter').addEventListener('input',function(e){
  filterStr=e.target.value.toLowerCase().trim();
  renderTable(state.Networks||[]);
});
function sortAps(aps){
  return aps.slice().sort(function(a,b){
    var av,bv;
    if(sortCol==='_int'){av=(a.CoChannelCount||0)+(a.AdjacentOverlapCount||0);bv=(b.CoChannelCount||0)+(b.AdjacentOverlapCount||0);}
    else{av=a[sortCol]!==null&&a[sortCol]!==undefined?a[sortCol]:'';bv=b[sortCol]!==null&&b[sortCol]!==undefined?b[sortCol]:'';}
    return av<bv?(sortAsc?-1:1):av>bv?(sortAsc?1:-1):0;
  });
}

function drawSpark(canvas,bssid){
  var h=hist[bssid]||[];
  var ctx=canvas.getContext('2d');
  var W=canvas.width,H=canvas.height;
  ctx.clearRect(0,0,W,H);
  if(h.length<2){ctx.fillStyle='#374151';ctx.fillRect(0,H/2-1,W,2);return;}
  var pts=h.slice(-30),step=W/(pts.length-1),MIN=-100,RNG=70;
  var lastCol=rssiCol(pts[pts.length-1].v);
  var g=ctx.createLinearGradient(0,0,0,H);
  g.addColorStop(0,'rgba(59,130,246,.25)');
  g.addColorStop(1,'rgba(59,130,246,0)');
  ctx.fillStyle=g;ctx.beginPath();
  pts.forEach(function(p,i){
    var x=i*step,y=H-Math.max(1,Math.min(H-1,(p.v-MIN)/RNG*H));
    if(i===0){ctx.moveTo(x,H);ctx.lineTo(x,y);}else ctx.lineTo(x,y);
  });
  ctx.lineTo((pts.length-1)*step,H);ctx.closePath();ctx.fill();
  ctx.strokeStyle=lastCol;ctx.lineWidth=1.5;ctx.lineJoin='round';ctx.beginPath();
  pts.forEach(function(p,i){
    var x=i*step,y=H-Math.max(1,Math.min(H-1,(p.v-MIN)/RNG*H));
    i===0?ctx.moveTo(x,y):ctx.lineTo(x,y);
  });
  ctx.stroke();
}

var prevRssi={};
function renderTable(aps){
  var fil=filterStr?aps.filter(function(a){return(a.Ssid||'').toLowerCase().indexOf(filterStr)>=0;}):aps;
  var srt=sortAps(fil);
  ge('net-count').textContent='('+srt.length+(filterStr?' / '+aps.length:'')+')';
  var tbody=ge('ap-tbody');
  var ex={};
  Array.from(tbody.querySelectorAll('tr[data-bssid]')).forEach(function(tr){ex[tr.dataset.bssid]=tr;});
  var frag=document.createDocumentFragment();
  srt.forEach(function(ap){
    var bssid=ap.Bssid||'';
    var pct=barPct(ap.Rssi),bc=rssiCol(ap.Rssi),g=ap.Grade||'F';
    var intv=(ap.CoChannelCount||0)+(ap.AdjacentOverlapCount||0);
    var intcls=intv>=4?'error':intv>=2?'warn':'muted';
    var util=ap.ChannelUtilization!=null?ap.ChannelUtilization+'%':'--';
    var trend=ap.SignalTrend>1.5?'\u2191 +'+ap.SignalTrend.toFixed(1):ap.SignalTrend<-1.5?'\u2193 '+ap.SignalTrend.toFixed(1):'\u2192';
    var trcls=ap.SignalTrend>1.5?'success':ap.SignalTrend<-1.5?'error':'muted';
    var mesh=ap.MeshNote?(' <span class=\'muted small\'>'+enc(ap.MeshNote)+'</span>'):'';
    var connStar=ap.IsConnected?'<span class=\'success\'>\u2605</span> ':'';
    var tr=ex[bssid];var isNew=!tr;
    if(isNew){tr=document.createElement('tr');tr.dataset.bssid=bssid;}
    if(ap.IsConnected)tr.classList.add('conn-row');else tr.classList.remove('conn-row');
    if(evilBssidSet[bssid.toLowerCase()])tr.classList.add('evil-twin-row');
    else tr.classList.remove('evil-twin-row');
    if(!isNew&&prevRssi[bssid]!==undefined&&prevRssi[bssid]!==ap.Rssi){
      tr.classList.remove('flash');void tr.offsetWidth;tr.classList.add('flash');
    }
    prevRssi[bssid]=ap.Rssi;
    tr.innerHTML=
      '<td>'+connStar+enc(ap.Ssid||'(piilotettu)')+mesh+'</td>'+
      '<td class=\'mono grade-'+g+'\'>'+ap.Rssi+' dBm</td>'+
      '<td><div class=\'rssi-wrap\'><div class=\'rssi-bar\' style=\'width:'+pct+'%;background:'+bc+'\'></div></div></td>'+
      '<td><canvas class=\'spark\' width=\'60\' height=\'22\' data-bssid=\''+enc(bssid)+'\'></canvas></td>'+
      '<td>'+enc(String(ap.Channel||'?'))+'</td>'+
      '<td class=\'muted\'>'+enc(ap.Band||'')+'</td>'+
      '<td class=\''+secCls(ap.Security||'')+'\'>'+enc(ap.Security||'?')+'</td>'+
      '<td class=\''+intcls+'\'>'+intv+'</td>'+
      '<td class=\'muted\'>'+util+'</td>'+
      '<td class=\'muted\'>\xb1'+(ap.SignalJitter||0).toFixed(1)+'</td>'+
      '<td class=\'accent\'>'+(ap.Score||0).toFixed(1)+'</td>'+
      '<td class=\''+trcls+'\'>'+trend+'</td>'+
      '<td class=\'muted small\'>'+enc(ap.Vendor||'')+'</td>';
    frag.appendChild(tr);
  });
  tbody.innerHTML='';tbody.appendChild(frag);
  tbody.querySelectorAll('canvas.spark').forEach(function(c){drawSpark(c,c.dataset.bssid);});
}

function renderCharts(aps){
  var top=aps.slice().sort(function(a,b){return a.Rssi-b.Rssi;}).slice(0,15);
  C.rssi.data.labels=top.map(function(a){return a.Ssid||'?';});
  C.rssi.data.datasets[0].data=top.map(function(a){return a.Rssi;});
  C.rssi.data.datasets[0].backgroundColor=top.map(function(a){return rssiCol(a.Rssi);});
  C.rssi.update();
  var chC={};
  aps.forEach(function(a){if(a.Channel>0)chC[a.Channel]=(chC[a.Channel]||0)+1;});
  var chK=Object.keys(chC).map(Number).sort(function(a,b){return a-b;});
  C.ch.data.labels=chK.map(function(k){return 'CH'+k;});
  C.ch.data.datasets[0].data=chK.map(function(k){return chC[k];});
  C.ch.update();
  var sec={};
  aps.forEach(function(a){var k=a.Security||'?';sec[k]=(sec[k]||0)+1;});
  var sK=Object.keys(sec).sort(function(a,b){return sec[b]-sec[a];});
  C.sec.data.labels=sK;
  C.sec.data.datasets[0].data=sK.map(function(k){return sec[k];});
  C.sec.data.datasets[0].backgroundColor=sK.map(secCol);
  C.sec.update();
  var sc=aps.slice().sort(function(a,b){return(b.Score||0)-(a.Score||0);}).slice(0,10);
  C.score.data.labels=sc.map(function(a){return a.Ssid||'?';});
  C.score.data.datasets[0].data=sc.map(function(a){return a.Score;});
  C.score.update();
}

var knownTs=new Set(alerts.map(function(a){return a.Time;}));
function renderAlerts(list){
  var sec=ge('alerts-section');
  if(!list||list.length===0){sec.hidden=true;return;}
  sec.hidden=false;
  ge('alert-badge').textContent='('+list.length+')';
  ge('alert-list').innerHTML=list.slice(0,30).map(function(a){
    var t=new Date(a.Time).toLocaleTimeString('fi-FI');
    return '<div class=\'alert-row t'+enc(a.Type||'')+'\'>'+
      '<span class=\'alert-ts\'>'+t+'</span>'+
      '<span class=\'alert-type\'>'+enc(a.Type||'')+'</span>'+
      '<span>'+enc(a.Bssid||'')+(a.Bssid?' \u2014 ':'')+enc(a.Message||'')+'</span></div>';
  }).join('');
}
function checkNew(list){
  if(!list)return;
  list.forEach(function(a){if(!knownTs.has(a.Time)){knownTs.add(a.Time);showToast(a);}});
}
function showToast(alert){
  var el=document.createElement('div');
  var tc=alert.Type==='EvilTwin'?'tevil':alert.Type==='NewAP'?'tok':'';
  // Kayttaa BMP-merkkeja (alle U+FFFF) — ei JS-surrogaattipareja
  var ic=alert.Type==='EvilTwin'?'\u26A0':alert.Type==='WeakSignal'?'\u2193':
         alert.Type==='NewAP'?'\u2B50':alert.Type==='Roaming'?'\u21AA':'\u2139';
  el.className='toast '+tc;
  el.innerHTML='<div class=\'toast-hd\'>'+ic+' '+enc(alert.Type||'')+'</div>'+
               '<div class=\'muted\'>'+enc(alert.Message||'')+'</div>';
  ge('toasts').appendChild(el);
  setTimeout(function(){
    el.classList.add('tout');
    setTimeout(function(){el.remove();},260);
  },4500);
}

function updateScan(d){
  var pill=ge('scan-pill'),dot=ge('scan-dot'),lbl=ge('scan-label');
  var run=!!d.IsScanRunning;
  pill.classList.toggle('running',run);
  dot.classList.toggle('running',run);
  var s=d.ScanStatus||'';
  lbl.textContent=run?'Skannaus...':s.indexOf('valmis')>=0?'Valmis \u2713':s.indexOf('virhe')>=0?'Virhe \u26A0':'Valmiustila';
  lbl.title=s;
}
function updateSpeed(sp){
  if(!sp)return;
  ge('s-ping').textContent=sp.PingMs<0?'\u2014':Math.round(sp.PingMs)+'';
  ge('s-dl').textContent=sp.ThroughputKBs>0?Math.round(sp.ThroughputKBs)+'':'\u2014';
  ge('s-ping').style.color=sp.PingMs>100?'var(--warn)':sp.PingMs>30?'var(--accent)':'var(--success)';
}

function render(d){
  if(!d)return;
  var aps=d.Networks||[];
  aps.forEach(function(a){pushH(a.Bssid,a.Rssi);});
  if(d.Timestamp)ge('ts').textContent=new Date(d.Timestamp).toLocaleString('fi-FI');
  if(d.BestChannel)ge('best-ch').textContent=d.BestChannel;
  ge('s-total').textContent=aps.length;
  ge('s-wpa3').textContent=aps.filter(function(a){return/3/.test(a.Security||'');}).length;
  ge('s-open').textContent=aps.filter(function(a){return a.Security==='Open';}).length;
  ge('s-alerts').textContent=d.AlertCount||0;
  renderTable(aps);
  renderCharts(aps);
  updateScan(d);
  updateSpeed(d.Speed);
  if(d.RecentAlerts)checkNew(d.RecentAlerts);
  updateSecurityPanel(d);
  updateForensicPanels(d);
  updateAnalyticsCharts();
}

/* ── Tietoturvapaneeli ─────────────────────────────────────────── */
var deauthAccum=[],evilBssidSet={},deauthChart=null;

function updateSecurityPanel(d){
  var level=d.ActiveAttackLevel||0;
  var deauths=d.RecentDeauths||[];
  var etAlerts=d.EvilTwinAlerts||[];
  var etBssids=d.EvilTwinBssids||[];
  var traffic=d.TrafficLog||[];
  // Kumuloi deauth-tapahtumat 60 s ikkunaan
  deauths.forEach(function(e){
    var key=e.Time+'|'+e.SenderBssid;
    if(!deauthAccum.find(function(x){return x._key===key;})){e._key=key;deauthAccum.push(e);}
  });
  var cut=Date.now()-60000;
  deauthAccum=deauthAccum.filter(function(e){return new Date(e.Time).getTime()>cut;});
  updateAttackBanner(level,d.AttackSummary||'');
  renderDeauthPanel(deauthAccum);
  renderEvilTwinPanel(etAlerts,etBssids);
  renderTrafficPanel(traffic);
}

function updateAttackBanner(level,summary){
  var banner=ge('attack-banner');if(!banner)return;
  if(level===0){banner.className='attack-banner hidden';return;}
  banner.className='attack-banner lvl'+level;
  ge('attack-title').className='attack-title lvl'+level;
  ge('attack-level-badge').className='attack-level-badge badge-lvl'+level;
  var labels={3:'VARMENNETTU',2:'TODENNÄKÖINEN',1:'EPÄILTY'};
  ge('attack-level-badge').textContent=labels[level]||'';
  var titles={3:'⚠ VARMENNETTU PMF-HYÖKKÄYS',2:'⚠ Todennäköinen hyökkäys',1:'⚠ Deauth-myrsky havaittu'};
  ge('attack-title').textContent=titles[level]||'Hyökkäys';
  ge('attack-msg').textContent=summary.length>120?summary.substring(0,117)+'...':summary;
}

function renderDeauthPanel(events){
  var badge=ge('deauth-count-badge');if(badge)badge.textContent=events.length||'';
  var now=Date.now();
  var buckets=new Array(12).fill(0),bcast=new Array(12).fill(0);
  events.forEach(function(e){
    var bi=Math.floor((now-new Date(e.Time).getTime())/5000);
    if(bi>=0&&bi<12){buckets[11-bi]++;if(e.IsBroadcast)bcast[11-bi]++;}
  });
  var canvas=ge('c-deauth');if(!canvas)return;
  if(!deauthChart){
    deauthChart=new Chart(canvas,{type:'bar',
      data:{labels:['-55','-50','-45','-40','-35','-30','-25','-20','-15','-10','-5','0'],
        datasets:[
          {label:'Deauth',data:buckets,backgroundColor:'rgba(245,158,11,.7)',borderRadius:3,borderWidth:0},
          {label:'Broadcast',data:bcast,backgroundColor:'rgba(239,68,68,.9)',borderRadius:3,borderWidth:0}
        ]},
      options:{plugins:{legend:{position:'bottom',labels:{font:{size:9},color:'#9ca3af'}}},
        animation:{duration:200},
        scales:{x:{ticks:{font:{size:9},color:'#6b7280'}},y:{min:0,ticks:{stepSize:1,font:{size:9},color:'#6b7280'}}}}
    });
  } else {
    deauthChart.data.datasets[0].data=buckets;
    deauthChart.data.datasets[1].data=bcast;
    deauthChart.update('none');
  }
  var list=ge('deauth-list');if(!list)return;
  var recent=events.slice().sort(function(a,b){return new Date(b.Time)-new Date(a.Time);}).slice(0,8);
  list.innerHTML=recent.map(function(e){
    var t=new Date(e.Time).toLocaleTimeString('fi-FI');
    var cls=e.IsBroadcast?'broadcast':'deauth',lbl=e.IsBroadcast?'BROADCAST':e.IsDeauth?'Deauth':'Disassoc';
    var pmfTag=e.IsFrameProtected?'':(!e.IsFrameProtected&&e.SenderBssid?'':' ');
    return '<div class=""sec-row""><span class=""sec-ts"">'+t+'</span>'+
      '<span class=""sec-lbl '+cls+'"">'+lbl+'</span>'+
      '<span class=""sec-detail"">'+enc(e.SenderBssid||'')+' → '+enc(e.TargetMac||'')+
      ' ('+enc(e.ReasonText||'Reason '+e.ReasonCode)+')</span></div>';
  }).join('');
}

function renderEvilTwinPanel(etAlerts,etBssids){
  evilBssidSet={};
  etBssids.forEach(function(b){evilBssidSet[b.toLowerCase()]=true;});
  var badge=ge('et-count-badge');if(badge)badge.textContent=etAlerts.length||'';
  var list=ge('eviltwin-list');if(!list)return;
  if(!etAlerts.length){list.innerHTML='<div class=""sec-row muted"">Ei havaintoja</div>';return;}
  var confLbl={3:'VARMENNETTU',2:'Todennäköinen',1:'Epäilty'};
  var confCls={3:'et-conf-3',2:'et-conf-2',1:'et-conf-1'};
  list.innerHTML=etAlerts.map(function(et){
    var t=new Date(et.DetectedAt).toLocaleTimeString('fi-FI');
    var cl=confCls[et.ConfidenceLevel]||'et-conf-1',lbl=confLbl[et.ConfidenceLevel]||'?';
    return '<div class=""sec-row""><span class=""sec-ts"">'+t+'</span>'+
      '<span class=""'+cl+'"">'+enc(lbl)+'</span>'+
      '<span class=""sec-detail""><b>'+enc(et.Ssid||'?')+'</b> &mdash; '+enc(et.Reason||'')+
      '<br><span class=""muted"">'+enc(et.SuspectBssid||'?')+'</span></span></div>';
  }).join('');
}

/* ── Forensiikka- ja estopaneelit ───────────────────────────── */
function updateForensicPanels(d){
  renderPcapPanel(d.PcapActiveCount||0, d.PcapRecentFiles||[]);
  renderRouterPanel(d.RouterBlockLog||[]);
  renderEapolPanel(d.EapolSummary||[], d.EapolStatus||'');
  renderHoneypotPanel(d.HoneypotEvents||[]);
  renderTiPanel(d.ThreatIntelStatus||'', d.ThreatIntelHits||[]);
}

// ── PCAP: vilkkuva piste + tiedostolista ──────────────────────
function renderPcapPanel(activeCount, files){
  var dot=ge('pcap-dot'); var badge=ge('pcap-active-badge');
  var row=ge('pcap-active-row'); var list=ge('pcap-list');
  if(!dot)return;
  if(activeCount>0){
    dot.className='pcap-dot-on';
    if(badge)badge.textContent=activeCount;
    if(row)row.classList.remove('hidden');
  } else {
    dot.className='pcap-dot-off';
    if(badge)badge.textContent='';
    if(row)row.classList.add('hidden');
  }
  if(!list)return;
  if(!files.length){
    list.innerHTML='<div class=""sec-row muted"">Ei tiedostoja &mdash; EnableAutoCapture=false</div>';
    return;
  }
  list.innerHTML=files.map(function(f){
    return '<div class=""sec-row""><span class=""sec-detail"">'+enc(f)+'</span></div>';
  }).join('');
}

// ── Reititinblokkaukset ───────────────────────────────────────
var _routerCount=0;
function renderRouterPanel(log){
  var badge=ge('router-badge'); var list=ge('router-list');
  if(badge)badge.textContent=log.length||'';
  if(!list)return;
  if(!log.length){
    list.innerHTML='<div class=""sec-row muted"">Ei estoja &mdash; konfiguroi Unifi/pfSense/OPNsense</div>';
    return;
  }
  // Flash uusimmat rivit
  var newCount=log.length-_routerCount;
  _routerCount=log.length;
  list.innerHTML=log.slice(0,15).map(function(r,i){
    var cls=i<newCount?'sec-row router-row-new':'sec-row';
    return '<div class=""'+cls+'"">' +
      '<span class=""sec-detail"">'+enc(r)+'</span></div>';
  }).join('');
}

// ── EAPOL / Handshake-aktiivisuus ────────────────────────────
function renderEapolPanel(summary, status){
  var badge=ge('eapol-badge'); var list=ge('eapol-list'); var stat=ge('eapol-status');
  var suspicious=summary.filter(function(e){return e.Suspicious;});
  if(badge)badge.textContent=suspicious.length>0?suspicious.length:'';
  if(stat)stat.textContent=status||'';
  if(!list)return;
  if(!summary.length){
    list.innerHTML='<div class=""sec-row muted"">Ei EAPOL-aktiivisuutta</div>';
    return;
  }
  list.innerHTML=summary.slice(0,8).map(function(e){
    var cls=e.Suspicious?'eapol-suspicious':'eapol-normal';
    var icon=e.Suspicious?'&#9888; ':'';
    return '<div class=""sec-row""><span class=""sec-ts"">'+enc(e.DistinctAps)+'AP</span>'+
      '<span class=""sec-detail '+cls+'"">'+icon+enc(e.ClientMac)+'</span></div>';
  }).join('');
}

// ── Honeypot-havainnot ────────────────────────────────────────
function renderHoneypotPanel(events){
  var badge=ge('honeypot-badge'); var list=ge('honeypot-list');
  if(badge)badge.textContent=events.length||'';
  if(!list)return;
  if(!events.length){
    list.innerHTML='<div class=""sec-row muted"">Ei havaintoja &mdash; ansa aktiivinen</div>';
    return;
  }
  list.innerHTML=events.slice(0,8).map(function(e){
    var t=new Date(e.Time).toLocaleTimeString('fi-FI');
    return '<div class=""sec-row honeypot-row"">'+
      '<span class=""sec-ts"">'+t+'</span>'+
      '<span class=""sec-lbl"">'+enc(e.Kind||'Probe')+'</span>'+
      '<span class=""sec-detail"">'+enc(e.SourceMac||'?')+
      ' &rarr; '+enc(e.TargetSsid||'?')+'</span></div>';
  }).join('');
}

function renderTiPanel(status, hits){
  var badge=ge('ti-badge'); var list=ge('ti-list'); var st=ge('ti-status');
  if(st)st.textContent=status||'';
  var threats=hits.filter(function(h){return h.Item2!=='Clean';});
  if(badge){
    badge.textContent=threats.length||'';
    badge.className='sec-badge '+(threats.length>0?'error':'');
  }
  if(!list)return;
  if(!threats.length){
    list.innerHTML='<div class=""sec-row muted"">Ei uhkia havaittu</div>';
    return;
  }
  list.innerHTML=threats.slice(0,12).map(function(h){
    var cls=h.Item2==='Malicious'?'ti-malicious':'ti-suspicious';
    var t=new Date(h.Item4).toLocaleTimeString('fi-FI');
    return '<div class=""sec-row '+cls+'"">'+
      '<span class=""sec-ts"">'+t+'</span>'+
      '<span class=""sec-lbl"">'+enc(h.Item2)+'</span>'+
      '<span class=""sec-detail"">'+enc(h.Item1)+
      ' <span class=""muted"">via '+enc(h.Item3)+'</span></span></div>';
  }).join('');
}

/* ── Inkrementaalinen DPI-tapahtuma SSE:stä ─────────────────── */
function injectDpiObservation(obs){
  // Lisää havainto client-side listaan (puskuri max 100 kpl)
  if(!window._dpiObs)window._dpiObs=[];
  // Päivitä jos sama nimi jo listalla
  var idx=window._dpiObs.findIndex(function(o){return o.Name===obs.Name;});
  if(idx>=0)window._dpiObs[idx]=obs;
  else window._dpiObs.unshift(obs);
  if(window._dpiObs.length>100)window._dpiObs.pop();

  // Blacklist-hälytys: kriittiset → toast
  if(obs.IsBlacklisted&&obs.BlacklistSeverity>=2){
    var sev=obs.BlacklistSeverity>=3?'KRIITTINEN':'Epaailyttava';
    var msg='['+sev+'] '+enc(obs.Name)+(obs.BlacklistReason?' ('+enc(obs.BlacklistReason)+')':'');
    showToast(msg,'tevil');
  }
  // Päivitä DPI-paneeli ja kaaviot välittömästi
  renderTrafficPanel(window._dpiObs);
  updateAnalyticsCharts();
}

function renderTrafficPanel(traffic){
  var list=ge('dpi-list');if(!list)return;
  // Käytä myös client-side puskuria jos saatavilla
  var obs=traffic||window._dpiObs||[];
  if(!obs.length){
    list.innerHTML='<div class=""sec-row muted"">Ei havaintoja &mdash; vain avoimet verkot</div>';return;
  }
  list.innerHTML=obs.slice(0,25).map(function(t){
    var ts=new Date(t.LastSeen).toLocaleTimeString('fi-FI');
    var kindCls=t.Kind==='DNS'?'dns':'sni';
    var svc=t.ServiceName?' <b>'+enc(t.ServiceName)+'</b>':'';
    var bl='';
    if(t.IsBlacklisted){
      var sevCls=t.BlacklistSeverity>=3?'et-conf-3':t.BlacklistSeverity>=2?'et-conf-2':'et-conf-1';
      var sevLbl=t.BlacklistSeverity>=3?'KRIITTINEN':'Epaailyttava';
      bl=' <span class=""'+sevCls+'"" title=""'+enc(t.BlacklistReason||'')+'"">['+sevLbl+']</span>';
    }
    return '<div class=""sec-row'+(t.IsBlacklisted?' bl-row':'')+'"">'+
      '<span class=""sec-ts"">'+ts+'</span>'+
      '<span class=""sec-lbl '+kindCls+'"">'+enc(t.Kind)+'</span>'+
      '<span class=""sec-detail"">'+enc(t.Name)+svc+bl+'</span></div>';
  }).join('');
}

var retry=1000,sseOn=false,evt=null;
function setConn(s){
  ge('conn-dot').className='conn-dot '+s;
  ge('conn-label').textContent=s==='live'?'Live':s==='connecting'?'Yhdist\xe4\xe4...':'Katkaistu';
}
function connect(){
  if(sseOn)return;
  sseOn=true;setConn('connecting');
  try{
    evt=new EventSource('/api/events');
    evt.onopen=function(){setConn('live');retry=1000;};
    evt.onmessage=function(e){
      try{
        var d=JSON.parse(e.data);
        state=d;render(d);
        if(d.RecentAlerts){alerts=d.RecentAlerts;renderAlerts(d.RecentAlerts.slice().reverse());}
        setConn('live');
      }catch(err){console.warn('SSE parse:',err);}
    };
    // Nimetty DPI-tapahtuma — tulee ilman snapshotia, vain DPI-paneeli päivittyy
    evt.addEventListener('dpi',function(e){
      try{injectDpiObservation(JSON.parse(e.data));}
      catch(err){console.warn('SSE dpi:',err);}
    });
    evt.onerror=function(){
      sseOn=false;setConn('offline');
      try{evt.close();}catch(e2){}
      retry=Math.min(retry*2,16000);
      setTimeout(connect,retry);
    };
  }catch(err){sseOn=false;setConn('offline');}
}

buildCharts();
render(state);
renderAlerts(alerts.slice().reverse());
if(location.protocol==='http:'||location.protocol==='https:')connect();
else{setConn('offline');ge('conn-label').textContent='Staattinen tiedosto';}
})();
");
            return sb.ToString();
        }
        private void WriteRecommendationIfNeeded(
            List<AnalyzedAccessPoint> aps, string bestCh, string dir)
        {
            if ((DateTime.Now - _lastRecommendationWrite) < TimeSpan.FromMinutes(5)) return;
            var chP = new Dictionary<int, double>();
            foreach (var ap in aps)
            {
                if (ap.Channel <= 0) continue;
                chP.TryGetValue(ap.Channel, out double c);
                chP[ap.Channel] = c + ap.InterferencePenalty;
            }
            double maxP = chP.Count > 0 ? chP.Values.Max() : 0;
            if (maxP < 20) return;
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine("Wi-Fi Analyzer — Kanavasuositus");
                sb.AppendLine($"Päivitetty: {DateTime.Now:dd.MM.yyyy HH:mm:ss}");
                sb.AppendLine(new string('─', 50));
                sb.AppendLine($"Kriittinen kanavaruuhka ({maxP:F0} pistettä).");
                sb.AppendLine($"Suositeltu 2.4 GHz kanava: {bestCh}");
                sb.AppendLine();
                sb.AppendLine("Kanavakuorma:");
                foreach (var kv in chP.OrderBy(x => x.Key))
                {
                    string band = kv.Key <= 14 ? "2.4G" : kv.Key <= 177 ? " 5G " : " 6G ";
                    sb.AppendLine($"  CH{kv.Key,3} [{band}] häiriöpisteet: {kv.Value:F0}");
                }
                sb.AppendLine($"\nOhje: Vaihda reitittimen kanava → {bestCh}.");
                WriteFileSafe(Path.Combine(dir, "recommendation.txt"), sb.ToString());
                _lastRecommendationWrite = DateTime.Now;
            }
            catch (Exception ex) { AppLogger.Log($"[Rec] {ex.Message}"); }
        }

        // ── Tiedostonkäsittely ────────────────────────────────────

        public static void WriteFileSafe(string path, string content)
        {
            string tmp = path + ".tmp";
            try
            {
                File.WriteAllText(tmp, content, Encoding.UTF8);
                if (File.Exists(path)) File.Replace(tmp, path, null);
                else                   File.Move(tmp, path);
            }
            catch (Exception ex)
            {
                AppLogger.Log($"[File] Replace: {ex.Message}");
                try { File.Copy(tmp, path, overwrite: true); } catch (Exception ce) { AppLogger.Log($"[File] Copy: {ce.Message}"); }
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
        }

        private static void PurgeOldReports(string dir, string pattern, TimeSpan maxAge)
        {
            try
            {
                DateTime cutoff = DateTime.Now - maxAge;
                foreach (string f in Directory.GetFiles(dir, pattern))
                    try { if (File.GetLastWriteTime(f) < cutoff) File.Delete(f); }
                    catch (Exception ex) { AppLogger.Log($"[Purge] {f}: {ex.Message}"); }
            }
            catch (Exception ex) { AppLogger.Log($"[Purge] {ex.Message}"); }
        }

        private string ResolveSaveDir()
            => string.IsNullOrWhiteSpace(_cfg.SaveDirectory) ? "." : _cfg.SaveDirectory;

        // Prometheus-muotoinen teksti (GET /metrics)
        public static string GetPrometheusMetrics(
            List<AnalyzedAccessPoint> aps, SpeedSample speed)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# HELP wifi_rssi Signal strength in dBm");
            sb.AppendLine("# TYPE wifi_rssi gauge");
            foreach (var ap in aps)
            {
                string lbl = $"bssid=\"{ap.Bssid}\",ssid=\"{EscPromLabel(ap.Ssid)}\",band=\"{ap.Band}\"";
                sb.AppendLine($"wifi_rssi{{{lbl}}} {ap.Rssi}");
                sb.AppendLine($"wifi_score{{{lbl}}} {ap.Score:F2}");
                sb.AppendLine($"wifi_interference{{{lbl}}} {ap.InterferencePenalty:F2}");
                if (ap.ChannelUtilization.HasValue)
                    sb.AppendLine($"wifi_channel_utilization{{{lbl}}} {ap.ChannelUtilization.Value}");
            }
            if (speed != null)
            {
                string gw = $"gateway=\"{speed.Gateway}\"";
                sb.AppendLine($"wifi_ping_ms{{{gw}}} {(speed.PingMs < 0 ? "NaN" : $"{speed.PingMs:F1}")}");
                sb.AppendLine($"wifi_download_kbs{{{gw}}} {speed.ThroughputKBs:F1}");
            }
            return sb.ToString();
        }

        private static string EscPromLabel(string s)
            => (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");

        // ── Prometheus alert_rules.yml ────────────────────────────

        private void ExportPrometheusAlertRules(string dir)
        {
            string yaml =
@"# WifiAnalyzerPro — Prometheus Alerting Rules
# Kopioi tämä tiedosto Prometheuksen rules-hakemistoon ja lisää
# prometheus.yml:ään: rule_files: ['alert_rules.yml']
groups:
  - name: wifi_security
    interval: 30s
    rules:

      - alert: WifiDeauthStorm
        expr: wifi_deauth_count_total > 10
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: ""Deauth-myrsky havaittu""
          description: ""{{ $labels.bssid }} on lähettänyt {{ $value }} Deauth-kehystä""

      - alert: WifiHighInterference
        expr: wifi_interference_penalty > 20
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: ""Korkea Wi-Fi-häiriö kanavalla""
          description: ""AP {{ $labels.ssid }} kanavalla {{ $labels.channel }}: häiriö {{ $value }}""

      - alert: WifiWeakSignal
        expr: wifi_rssi_dbm < -80
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: ""Heikko Wi-Fi-signaali""
          description: ""{{ $labels.ssid }}: RSSI {{ $value }} dBm""

      - alert: WifiOpenNetwork
        expr: wifi_security_open == 1
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: ""Avoin Wi-Fi-verkko havaittu""
          description: ""{{ $labels.ssid }} ({{ $labels.bssid }}) on suojaamaton""

      - alert: WifiHighChannelLoad
        expr: wifi_channel_utilization_pct > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: ""Wi-Fi-kanavakuorma korkea""
          description: ""{{ $labels.bssid }}: kanavan käyttöaste {{ $value }} %""

      - alert: WifiEvilTwin
        expr: wifi_evil_twin_detected == 1
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: ""Evil Twin -tukiasema havaittu""
          description: ""SSID {{ $labels.ssid }}: väärennetty AP {{ $labels.bssid }}""

      - alert: WifiThreatIntelHit
        expr: wifi_threat_intel_hits_total > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: ""Uhkatiedustelu: haitallinen domain havaittu""
          description: ""{{ $value }} osumaa uhkatietokannassa viimeisen skannauksen aikana""
";
            WriteFileSafe(Path.Combine(dir, "alert_rules.yml"), yaml);
            AppLogger.Log("[Prometheus] alert_rules.yml kirjoitettu");
        }

        // ── Grafana dashboard JSON ─────────────────────────────────

        private void ExportGrafanaDashboard(string dir)
        {
            // Grafana 10+ yhteensopiva dashboard JSON
            string json = @"{
  ""__inputs"": [{ ""name"": ""DS_PROMETHEUS"", ""label"": ""Prometheus"",
                   ""type"": ""datasource"", ""pluginId"": ""prometheus"" }],
  ""title"": ""WifiAnalyzerPro"",
  ""uid"":  ""wifianalyzer-main"",
  ""schemaVersion"": 39,
  ""refresh"": ""30s"",
  ""time"": { ""from"": ""now-1h"", ""to"": ""now"" },
  ""panels"": [
    { ""id"":1, ""type"":""timeseries"", ""title"":""RSSI per AP (dBm)"",
      ""gridPos"":{ ""x"":0,""y"":0,""w"":12,""h"":8 },
      ""targets"":[{ ""datasource"":""${DS_PROMETHEUS}"",
        ""expr"":""wifi_rssi_dbm"",""legendFormat"":""{{ssid}} ({{channel}})"" }],
      ""fieldConfig"":{ ""defaults"":{
        ""unit"":""dBm"", ""thresholds"":{ ""steps"":[
          {""color"":""red"",""value"":-100},
          {""color"":""orange"",""value"":-80},
          {""color"":""yellow"",""value"":-70},
          {""color"":""green"",""value"":-60}]}}} },
    { ""id"":2, ""type"":""timeseries"", ""title"":""Häiriöpisteet per AP"",
      ""gridPos"":{ ""x"":12,""y"":0,""w"":12,""h"":8 },
      ""targets"":[{ ""datasource"":""${DS_PROMETHEUS}"",
        ""expr"":""wifi_interference_penalty"",""legendFormat"":""{{ssid}}"" }] },
    { ""id"":3, ""type"":""stat"", ""title"":""Havaitut AP:t"",
      ""gridPos"":{ ""x"":0,""y"":8,""w"":4,""h"":4 },
      ""targets"":[{ ""datasource"":""${DS_PROMETHEUS}"",
        ""expr"":""count(wifi_rssi_dbm)"" }] },
    { ""id"":4, ""type"":""stat"", ""title"":""Deauth-kehykset (viim. 5 min)"",
      ""gridPos"":{ ""x"":4,""y"":8,""w"":4,""h"":4 },
      ""targets"":[{ ""datasource"":""${DS_PROMETHEUS}"",
        ""expr"":""increase(wifi_deauth_count_total[5m])"" }],
      ""fieldConfig"":{ ""defaults"":{ ""thresholds"":{ ""steps"":[
        {""color"":""green"",""value"":0},
        {""color"":""orange"",""value"":5},
        {""color"":""red"",""value"":20}]}}} },
    { ""id"":5, ""type"":""stat"", ""title"":""Kanavakuorma % (max)"",
      ""gridPos"":{ ""x"":8,""y"":8,""w"":4,""h"":4 },
      ""targets"":[{ ""datasource"":""${DS_PROMETHEUS}"",
        ""expr"":""max(wifi_channel_utilization_pct)"" }],
      ""fieldConfig"":{ ""defaults"":{ ""unit"":""%"",
        ""thresholds"":{ ""steps"":[
          {""color"":""green"",""value"":0},
          {""color"":""orange"",""value"":60},
          {""color"":""red"",""value"":80}]}}} },
    { ""id"":6, ""type"":""stat"", ""title"":""TI-uhkia havaittu"",
      ""gridPos"":{ ""x"":12,""y"":8,""w"":4,""h"":4 },
      ""targets"":[{ ""datasource"":""${DS_PROMETHEUS}"",
        ""expr"":""wifi_threat_intel_hits_total"" }],
      ""fieldConfig"":{ ""defaults"":{ ""thresholds"":{ ""steps"":[
        {""color"":""green"",""value"":0},
        {""color"":""red"",""value"":1}]}}} },
    { ""id"":7, ""type"":""timeseries"", ""title"":""Ping (ms)"",
      ""gridPos"":{ ""x"":0,""y"":12,""w"":12,""h"":7 },
      ""targets"":[{ ""datasource"":""${DS_PROMETHEUS}"",
        ""expr"":""wifi_ping_ms"",""legendFormat"":""Ping {{gateway}}"" }],
      ""fieldConfig"":{ ""defaults"":{ ""unit"":""ms"" }} },
    { ""id"":8, ""type"":""timeseries"", ""title"":""Kaistanopeus (KB/s)"",
      ""gridPos"":{ ""x"":12,""y"":12,""w"":12,""h"":7 },
      ""targets"":[{ ""datasource"":""${DS_PROMETHEUS}"",
        ""expr"":""wifi_throughput_kbps"",""legendFormat"":""Latausnopeus"" }],
      ""fieldConfig"":{ ""defaults"":{ ""unit"":""KBs"" }} }
  ]
}";
            WriteFileSafe(Path.Combine(dir, "grafana_dashboard.json"), json);
            AppLogger.Log("[Grafana] grafana_dashboard.json kirjoitettu");
        }

        private static string HE(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
                    .Replace("\"", "&quot;").Replace("'", "&#39;");
        }

        // ── Compliance-raportti ───────────────────────────────────

        /// <summary>
        /// Generoi PCI-DSS 4.0 + ISO 27001 -vaatimustenmukaisuusraportin HTML-tiedostoon.
        /// Palauttaa tallennetun tiedoston polun.
        /// </summary>
        public string ExportComplianceReport(ComplianceReport report, string outputDir = ".")
        {
            string path = System.IO.Path.Combine(outputDir,
                $"compliance_{DateTime.Now:yyyyMMdd_HHmmss}.html");
            try
            {
                System.IO.File.WriteAllText(path, BuildComplianceHtml(report),
                    System.Text.Encoding.UTF8);
                AppLogger.Log($"[Compliance] Raportti: {path}");
            }
            catch (Exception ex) { AppLogger.Log($"[Compliance] Virhe: {ex.Message}"); }
            return path;
        }

        private static string BuildComplianceHtml(ComplianceReport r)
        {
            var sb = new System.Text.StringBuilder();
            string gradeColor = r.OverallGrade switch
            {
                "A" => "#10b981", "B" => "#3b82f6", "C" => "#f59e0b",
                "D" => "#f97316", _   => "#ef4444"
            };

            sb.Append(@"<!DOCTYPE html><html lang='fi'><head><meta charset='UTF-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Wi-Fi Compliance Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e2e8f0;padding:24px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px;
  padding-bottom:16px;border-bottom:1px solid #2d3748}
.title{font-size:1.6em;font-weight:700;color:#f1f5f9}
.subtitle{color:#94a3b8;font-size:.9em;margin-top:4px}
.grade-box{text-align:center;background:#1e2533;border-radius:12px;padding:18px 28px}
.grade-letter{font-size:3em;font-weight:900;line-height:1}
.grade-score{color:#94a3b8;font-size:.9em}
.summary{display:flex;gap:14px;margin-bottom:24px;flex-wrap:wrap}
.summary-card{flex:1;min-width:120px;background:#1e2533;border-radius:10px;
  padding:14px 18px;text-align:center}
.summary-card .num{font-size:2em;font-weight:700}
.summary-card .lbl{color:#94a3b8;font-size:.8em;margin-top:4px}
.pass{color:#10b981}.fail{color:#ef4444}.warn{color:#f59e0b}.info{color:#60a5fa}
.rules{display:grid;gap:12px}
.rule{background:#1e2533;border-radius:10px;padding:16px 20px;
  border-left:4px solid transparent}
.rule.pass{border-color:#10b981}.rule.fail{border-color:#ef4444}
.rule.warning{border-color:#f59e0b}.rule.info{border-color:#60a5fa}
.rule-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px}
.rule-id{font-size:.78em;color:#94a3b8;font-family:monospace}
.rule-std{font-size:.75em;background:#2d3748;border-radius:4px;padding:2px 7px;color:#94a3b8}
.rule-name{font-weight:600;color:#f1f5f9;margin-bottom:4px}
.rule-desc{font-size:.85em;color:#94a3b8;margin-bottom:8px}
.rule-detail{font-size:.9em;padding:8px 12px;border-radius:6px;background:#0f1117}
.status-badge{font-size:.78em;font-weight:700;padding:3px 10px;border-radius:20px}
.badge-pass{background:#064e3b;color:#34d399}
.badge-fail{background:#450a0a;color:#f87171}
.badge-warning{background:#451a03;color:#fbbf24}
.badge-info{background:#1e3a5f;color:#60a5fa}
.affected{font-size:.78em;color:#94a3b8;margin-top:6px;font-family:monospace}
.footer{margin-top:28px;color:#475569;font-size:.8em;text-align:center}
</style></head><body>
<div class='header'>
  <div>
    <div class='title'>Wi-Fi Compliance Report</div>
    <div class='subtitle'>PCI-DSS 4.0 &amp; ISO 27001:2022 &mdash; ");
            sb.Append(HE(r.GeneratedAt.ToString("dd.MM.yyyy HH:mm:ss")));
            sb.Append(@"</div>
  </div>
  <div class='grade-box'>");
            sb.Append($"<div class='grade-letter' style='color:{gradeColor}'>{r.OverallGrade}</div>");
            sb.Append($"<div class='grade-score'>{r.Score}/100 pistettä</div>");
            sb.Append(@"</div></div>
<div class='summary'>");
            sb.Append($"<div class='summary-card'><div class='num pass'>{r.PassCount}</div><div class='lbl'>Pass</div></div>");
            sb.Append($"<div class='summary-card'><div class='num fail'>{r.FailCount}</div><div class='lbl'>Fail</div></div>");
            sb.Append($"<div class='summary-card'><div class='num warn'>{r.WarnCount}</div><div class='lbl'>Warning</div></div>");
            sb.Append($"<div class='summary-card'><div class='num'>{r.Rules.Count}</div><div class='lbl'>Sääntöä tarkistettu</div></div>");
            sb.Append("</div><div class='rules'>");

            foreach (var rule in r.Rules)
            {
                string cls   = rule.Status.ToString().ToLower();
                string badge = rule.Status switch
                {
                    ComplianceStatus.Pass    => "<span class='status-badge badge-pass'>✓ PASS</span>",
                    ComplianceStatus.Fail    => "<span class='status-badge badge-fail'>✗ FAIL</span>",
                    ComplianceStatus.Warning => "<span class='status-badge badge-warning'>⚠ WARNING</span>",
                    _                        => "<span class='status-badge badge-info'>ℹ INFO</span>"
                };

                sb.Append($"<div class='rule {cls}'>");
                sb.Append("<div class='rule-header'>");
                sb.Append($"<div><span class='rule-id'>{HE(rule.Id)}</span>");
                sb.Append($"&nbsp;<span class='rule-std'>{HE(rule.Standard)}</span></div>");
                sb.Append(badge);
                sb.Append("</div>");
                sb.Append($"<div class='rule-name'>{HE(rule.Requirement)}</div>");
                sb.Append($"<div class='rule-desc'>{HE(rule.Description)}</div>");
                sb.Append($"<div class='rule-detail'>{HE(rule.Detail)}</div>");
                if (rule.AffectedBssids?.Count > 0)
                    sb.Append($"<div class='affected'>Kohdistuu: {HE(string.Join(", ", rule.AffectedBssids.Take(5)))}</div>");
                sb.Append("</div>");
            }

            sb.Append("</div>");
            sb.Append($"<div class='footer'>WifiAnalyzerPro &mdash; Automaattinen compliance-tarkistus &mdash; {r.GeneratedAt:yyyy}</div>");
            sb.Append("</body></html>");
            return sb.ToString();
        }
    }
}

