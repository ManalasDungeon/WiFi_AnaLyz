using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Lähettää MAC-estokäskyn hallittuun verkkoinfraan REST-rajapinnan kautta.
    ///
    /// Tuetut laitteet (kaikki omaan infraan):
    ///   • Unifi Network Application (v7+, REST + cookie-auth)
    ///   • pfSense REST API (pfSense+ 22.05+ tai CE + API-paketti)
    ///   • OPNsense REST API (API-avainpari)
    ///
    /// Toimintamalli:
    ///   Kun IDS tai Honeypot laukaisee hälytyksen, engine kutsuu
    ///   BlockMacAsync(mac, reason). Kutsu menee kaikkiin konfiguroituihin
    ///   kohteihin samanaikaisesti (Task.WhenAll). Cooldown per MAC estää
    ///   päällekkäiset kutsut.
    ///
    /// Konfiguraatio wifi_config.json:ssa:
    ///   "UnifiControllerUrl": "https://192.168.1.1:8443"
    ///   "UnifiUsername": "admin"
    ///   "UnifiPassword": "secret"
    ///   "PfSenseUrl": "https://192.168.1.1"
    ///   "PfSenseApiKey": "..."
    ///   "OPNsenseUrl": "https://192.168.1.1"
    ///   "OPNsenseKey": "..." / "OPNsenseSecret": "..."
    /// </summary>
    public sealed class RouterContainment : IDisposable
    {
        // HttpClient hyväksyy self-signed-sertifikaatit (kotireitittimillä yleinen)
        private static readonly HttpClient _http = new(new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        })
        { Timeout = TimeSpan.FromSeconds(10) };

        private WifiConfig _cfg;
        private readonly ConcurrentDictionary<string, DateTime> _blocked =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> _blockLog = new();
        private readonly object _logLock = new();
        private const int CooldownMinutes = 60; // sama MAC enintään kerran per tunti

        public RouterContainment(WifiConfig cfg) => _cfg = cfg;

        public void Apply(WifiConfig cfg) => _cfg = cfg;

        /// <summary>
        /// Estää MAC-osoitteen kaikissa konfiguroeissa reitittimissä.
        /// Fire-and-forget: palauttaa välittömästi, lähettää taustalla.
        /// </summary>
        public void BlockMac(string mac, string reason)
        {
            if (string.IsNullOrWhiteSpace(mac)) return;
            if (!ShouldBlock(mac)) return;

            AppLogger.Log($"[Containment] Estetään {mac}: {reason}");
            lock (_logLock) _blockLog.Add($"[{DateTime.Now:HH:mm:ss}] BLOCK {mac} — {reason}");

            Task.Run(async () =>
            {
                var tasks = new List<Task>();

                if (!string.IsNullOrWhiteSpace(_cfg.UnifiControllerUrl))
                    tasks.Add(BlockUnifiAsync(mac, reason));

                if (!string.IsNullOrWhiteSpace(_cfg.PfSenseUrl))
                    tasks.Add(BlockPfSenseAsync(mac, reason));

                if (!string.IsNullOrWhiteSpace(_cfg.OPNsenseUrl))
                    tasks.Add(BlockOPNsenseAsync(mac, reason));

                await Task.WhenAll(tasks).ConfigureAwait(false);
            });
        }

        // ── Unifi Network Application ─────────────────────────────

        /// <summary>
        /// Estää aseman Unifi Controllerissa.
        ///
        /// API-kulku:
        ///   1. POST /api/login → kirjautuminen, cookie palautuu
        ///   2. POST /api/s/{site}/cmd/stamgr {cmd:"block-sta", mac:...}
        ///   3. GET  /api/logout
        ///
        /// Vaihtoehto (Unifi OS v7.3+): käytä API-avainparia
        ///   X-API-KEY: header (jos UnifiApiKey on asetettu)
        /// </summary>
        private async Task BlockUnifiAsync(string mac, string reason)
        {
            string base_ = _cfg.UnifiControllerUrl!.TrimEnd('/');
            string site  = string.IsNullOrWhiteSpace(_cfg.UnifiSite) ? "default" : _cfg.UnifiSite;

            try
            {
                // Kirjautuminen
                string loginJson = JsonSerializer.Serialize(new
                {
                    username = _cfg.UnifiUsername ?? "",
                    password = _cfg.UnifiPassword ?? ""
                });
                using var loginResp = await _http.PostAsync(
                    $"{base_}/api/login",
                    new StringContent(loginJson, Encoding.UTF8, "application/json"))
                    .ConfigureAwait(false);

                if (!loginResp.IsSuccessStatusCode)
                {
                    AppLogger.Log($"[Unifi] Kirjautuminen epäonnistui: HTTP {(int)loginResp.StatusCode}");
                    return;
                }

                // Esto
                string blockJson = JsonSerializer.Serialize(new { cmd = "block-sta", mac });
                using var blockResp = await _http.PostAsync(
                    $"{base_}/api/s/{site}/cmd/stamgr",
                    new StringContent(blockJson, Encoding.UTF8, "application/json"))
                    .ConfigureAwait(false);

                if (blockResp.IsSuccessStatusCode)
                    AppLogger.Log($"[Unifi] MAC estetty: {mac}");
                else
                    AppLogger.Log($"[Unifi] Esto epäonnistui: HTTP {(int)blockResp.StatusCode}");

                // Kirjautuminen ulos
                await _http.GetAsync($"{base_}/api/logout").ConfigureAwait(false);
            }
            catch (Exception ex) { AppLogger.Log($"[Unifi] {ex.Message}"); }
        }

        // ── pfSense REST API ──────────────────────────────────────

        /// <summary>
        /// Lisää MAC-osoitteen pfSense:n palomuurisääntölistaan.
        ///
        /// pfSense Plus REST API (22.05+):
        ///   POST /api/v1/firewall/alias/host
        ///   Authorization: Basic {base64(user:pass)} tai X-API-Key: {key}
        ///
        /// Lisää MAC:n aliakseen nimeltä PfSenseMacAlias ("wifi_blacklist" oletuksena).
        /// Tämä alias kytketään palomuurisääntöön joka estää kyseisen MAC:n liikenteen.
        /// </summary>
        private async Task BlockPfSenseAsync(string mac, string reason)
        {
            string base_ = _cfg.PfSenseUrl!.TrimEnd('/');
            string alias  = string.IsNullOrWhiteSpace(_cfg.PfSenseMacAlias)
                ? "wifi_blacklist" : _cfg.PfSenseMacAlias;

            try
            {
                // pfSense suosii IP:tä MAC:in sijaan — muunnos ohitetaan,
                // koska Layer 2 MAC-esto tehdään aliaksen kautta
                var payload = new
                {
                    name    = alias,
                    address = mac,
                    detail  = $"WifiAnalyzerPro: {reason}"
                };

                string apiKey = _cfg.PfSenseApiKey ?? "";
                HttpRequestMessage req = new(HttpMethod.Post,
                    $"{base_}/api/v1/firewall/alias/host")
                {
                    Content = new StringContent(
                        JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
                };

                if (!string.IsNullOrWhiteSpace(apiKey))
                    req.Headers.Add("X-API-Key", apiKey);
                else
                {
                    string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                        $"{_cfg.PfSenseUsername ?? "admin"}:{_cfg.PfSensePassword ?? ""}"));
                    req.Headers.Add("Authorization", $"Basic {b64}");
                }

                using var resp = await _http.SendAsync(req).ConfigureAwait(false);
                if (resp.IsSuccessStatusCode)
                    AppLogger.Log($"[pfSense] MAC lisätty aliakseen '{alias}': {mac}");
                else
                    AppLogger.Log($"[pfSense] Virhe: HTTP {(int)resp.StatusCode}");
            }
            catch (Exception ex) { AppLogger.Log($"[pfSense] {ex.Message}"); }
        }

        // ── OPNsense REST API ─────────────────────────────────────

        /// <summary>
        /// Lisää MAC-osoitteen OPNsense:n palomuurialiakseen.
        ///
        /// OPNsense REST API:
        ///   POST /api/firewall/alias/addHost/{alias}/{address}
        ///   Authorization: Basic {base64(key:secret)}
        ///
        /// Alias luodaan WifiConfig.OPNsenseMacAlias:lla (oletus "wifi_blacklist").
        /// Apply-kutsu aktivoi säännön välittömästi.
        /// </summary>
        private async Task BlockOPNsenseAsync(string mac, string reason)
        {
            string base_ = _cfg.OPNsenseUrl!.TrimEnd('/');
            string alias  = string.IsNullOrWhiteSpace(_cfg.OPNsenseMacAlias)
                ? "wifi_blacklist" : _cfg.OPNsenseMacAlias;

            try
            {
                string key    = _cfg.OPNsenseKey    ?? "";
                string secret = _cfg.OPNsenseSecret ?? "";
                string b64    = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{key}:{secret}"));

                // Lisää host aliakseen
                HttpRequestMessage addReq = new(HttpMethod.Post,
                    $"{base_}/api/firewall/alias/addHost/{alias}/{Uri.EscapeDataString(mac)}")
                {
                    Content = new StringContent("{}", Encoding.UTF8, "application/json")
                };
                addReq.Headers.Add("Authorization", $"Basic {b64}");

                using var addResp = await _http.SendAsync(addReq).ConfigureAwait(false);
                if (!addResp.IsSuccessStatusCode)
                {
                    AppLogger.Log($"[OPNsense] addHost virhe: HTTP {(int)addResp.StatusCode}");
                    return;
                }

                // Aktivoi muutos välittömästi
                HttpRequestMessage applyReq = new(HttpMethod.Post,
                    $"{base_}/api/firewall/alias/reconfigure")
                {
                    Content = new StringContent("{}", Encoding.UTF8, "application/json")
                };
                applyReq.Headers.Add("Authorization", $"Basic {b64}");

                using var applyResp = await _http.SendAsync(applyReq).ConfigureAwait(false);
                AppLogger.Log(applyResp.IsSuccessStatusCode
                    ? $"[OPNsense] MAC estetty ja aktivoitu: {mac}"
                    : $"[OPNsense] Apply virhe: HTTP {(int)applyResp.StatusCode}");
            }
            catch (Exception ex) { AppLogger.Log($"[OPNsense] {ex.Message}"); }
        }

        // ── Apurakenteet ──────────────────────────────────────────

        private bool ShouldBlock(string mac)
        {
            if (_blocked.TryGetValue(mac, out var last) &&
                (DateTime.Now - last).TotalMinutes < CooldownMinutes)
                return false;
            _blocked[mac] = DateTime.Now;
            return true;
        }

        public List<string> GetBlockLog()
        {
            lock (_logLock) return new List<string>(_blockLog);
        }

        public void Dispose() { }
    }
}
