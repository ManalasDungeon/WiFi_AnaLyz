using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    // ── Datatyypit ────────────────────────────────────────────────

    public enum ThreatLevel { Clean = 0, Suspicious = 1, Malicious = 2 }

    public class ThreatIntelResult
    {
        public string      Domain       { get; set; }
        public ThreatLevel Level        { get; set; }
        public int         PulseCount   { get; set; }  // OTX: esiintymisiä uhkatietokannoissa
        public int         AbuseScore   { get; set; }  // AbuseIPDB: 0–100
        public int Score { get; set; }  // Yhdistelmä PulseCount ja AbuseScore (ei API:sta)
        public string      Source       { get; set; }  // "OTX" / "AbuseIPDB" / "Cache"
        public DateTime    Timestamp    { get; set; } = DateTime.Now;
    }

    /// <summary>
    /// Ulkoinen uhkatiedustelu: AlienVault OTX (domainit) + AbuseIPDB (IP-osoitteet).
    ///
    /// Arkkitehtuuri — kolme kerrosta:
    ///   L1 Muisticache  — ConcurrentDictionary, TTL 24 h (malware-domainit pysyvät)
    ///   In-flight dedup — sama domain ei aiheuta kahta samanaikaista API-kutsua
    ///   Rate limiter    — SemaphoreSlim, max MaxRequestsPerHour / tunti
    ///
    /// Whitelist         — Tunnistettuja palveluita (Google, Apple jne.) ei koskaan katsota.
    ///   DpiAnalyzer tunnistaa nämä jo palvelunimillä → TI jää vain tuntemattomille.
    ///
    /// Integrointi:
    ///   Kutsutaan HiddenNodeTracker.ObservationRecorded -tapahtumasta kun domain
    ///   on tuntematon (ServiceName == null) eikä se ole jo blacklistattu.
    ///   Callback laukaistaan taustasäikeessä — ei blokaa packet-käsittelijää.
    /// </summary>
    public sealed class ThreatIntelClient : IDisposable
    {
        private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

        // ── Konfiguraatio ─────────────────────────────────────────
        private volatile string _otxApiKey     = "";
        private volatile string _abuseApiKey   = "";
        private volatile int    _cacheTtlHours = 24;
        private volatile int    _maxPerHour    = 100;
        private volatile bool   _enabled       = false;
        private volatile int    _otxThreshold  = 2;   // pulses ≥ tämä → Malicious
        private volatile int    _abuseThreshold = 50; // score ≥ tämä → Suspicious, ≥80 → Malicious

        // ── L1-cache ──────────────────────────────────────────────
        private sealed class CacheEntry
        {
            public ThreatLevel Level;
            public int         Score;
            public string      Source;
            public DateTime    Expires;
        }
        private readonly ConcurrentDictionary<string, CacheEntry> _cache =
            new(StringComparer.OrdinalIgnoreCase);

        // ── In-flight dedup ───────────────────────────────────────
        private readonly ConcurrentDictionary<string, byte> _inFlight =
            new(StringComparer.OrdinalIgnoreCase);

        // ── Rate limiter ──────────────────────────────────────────
        private readonly SemaphoreSlim _rateSlot     = new(1, 1);
        private int    _requestsThisHour  = 0;
        private long _hourWindowStart = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        // ── Tilasto ───────────────────────────────────────────────
        private long _totalQueries    = 0;
        private long _cacheHits       = 0;
        private long _apiCalls        = 0;
        private long _threatsFound    = 0;
        private volatile string _status = "TI: pois käytöstä";

        public string Status => _status;

        // ── Whitelist — ei koskaan katsota API:sta ────────────────
        // Nämä tunnistetaan jo DpiAnalyzer.ServiceRules:ssa,
        // mutta whitelist on defensiivinen kerros rate-limittien säästämiseksi.
        private static readonly HashSet<string> Whitelist = new(StringComparer.OrdinalIgnoreCase)
        {
            "google.com","googleapis.com","googleusercontent.com","gstatic.com","googlevideo.com",
            "apple.com","icloud.com","mzstatic.com","appleid.apple.com",
            "microsoft.com","office.com","office365.com","microsoftonline.com","live.com",
            "windows.com","windowsupdate.com","update.microsoft.com",
            "amazon.com","amazonaws.com","cloudfront.net","awsstatic.com",
            "azure.com","azureedge.net","azurewebsites.net",
            "cloudflare.com","cloudflare-dns.com","1.1.1.1",
            "akamai.com","akamaized.net","akamaitechnologies.com",
            "fastly.com","fastlylb.net",
            "netflix.com","nflxvideo.net","nflximg.net",
            "youtube.com","youtu.be","ytimg.com",
            "facebook.com","fbcdn.net","instagram.com","cdninstagram.com",
            "twitter.com","x.com","twimg.com",
            "discord.com","discordapp.com",
            "slack.com","slack-edge.com",
            "spotify.com","scdn.co","spotifycdn.com",
            "dropbox.com","onedrive.com","sharepoint.com",
            "zoom.us","zoom.com",
            "github.com","githubusercontent.com",
        };

        public ThreatIntelClient(WifiConfig cfg) => Apply(cfg);

        public void Apply(WifiConfig cfg)
        {
            _otxApiKey    = cfg.OtxApiKey    ?? "";
            _abuseApiKey  = cfg.AbuseIpDbApiKey ?? "";
            _cacheTtlHours = Math.Max(1, cfg.ThreatIntelCacheTtlHours);
            _maxPerHour    = Math.Max(10, cfg.ThreatIntelMaxRequestsPerHour);
            _enabled       = cfg.EnableThreatIntel &&
                             (!string.IsNullOrWhiteSpace(_otxApiKey) ||
                              !string.IsNullOrWhiteSpace(_abuseApiKey));
            _status = _enabled
                ? $"TI: aktiivinen — OTX {(!string.IsNullOrEmpty(_otxApiKey) ? "on" : "off")}" +
                  $", AbuseIPDB {(!string.IsNullOrEmpty(_abuseApiKey) ? "on" : "off")}"
                : "TI: pois käytöstä (aseta OtxApiKey tai AbuseIpDbApiKey)";
        }

        // ── Julkinen API ──────────────────────────────────────────

        /// <summary>
        /// Palauttaa välimuistin tuloksen välittömästi (null jos ei löydy).
        /// Kutsutaan synkronisesti pakettikäsittelijästä.
        /// </summary>
        public ThreatIntelResult CheckCached(string domain)
        {
            if (!_enabled || string.IsNullOrWhiteSpace(domain)) return null;
            string root = GetRootDomain(domain);
            if (Whitelist.Contains(root)) return null;

            if (_cache.TryGetValue(root, out var e) && e.Expires > DateTime.Now)
            {
                Interlocked.Increment(ref _cacheHits);
                return e.Level == ThreatLevel.Clean ? null : new ThreatIntelResult
                {
                    Domain = root, Level = e.Level,
                    Score = e.Score, Source = e.Source + " (cache)"
                };
            }
            return null;
        }

        /// <summary>
        /// Jonottaa tausta-API-kutsun. Jos cache-osuma tai jo käynnissä → ei kutsuta.
        /// Callback kutsutaan taustasäikeestä vain jos uhka löytyy (ei Clean-tuloksia).
        /// </summary>
        public void EnqueueLookup(string domain, Action<ThreatIntelResult> onThreat)
        {
            if (!_enabled || string.IsNullOrWhiteSpace(domain)) return;
            string root = GetRootDomain(domain);
            if (Whitelist.Contains(root)) return;

            // Ei kutsuta jos cache on tuore
            if (_cache.TryGetValue(root, out var ce) && ce.Expires > DateTime.Now) return;

            // In-flight dedup — ei kahta samanaikaista kutsua samalle domainille
            if (!_inFlight.TryAdd(root, 1)) return;

            Interlocked.Increment(ref _totalQueries);

            Task.Run(async () =>
            {
                try
                {
                    var result = await LookupAsync(root).ConfigureAwait(false);
                    if (result == null) return;

                    var entry = new CacheEntry
                    {
                        Level   = result.Level,
                        Score   = result.Level == ThreatLevel.Malicious
                                    ? result.PulseCount * 10 + result.AbuseScore
                                    : result.AbuseScore,
                        Source  = result.Source,
                        Expires = DateTime.Now.AddHours(_cacheTtlHours)
                    };
                    _cache[root] = entry;

                    if (result.Level > ThreatLevel.Clean)
                    {
                        Interlocked.Increment(ref _threatsFound);
                        AppLogger.Log($"[TI] {result.Level}: {root} " +
                            $"(OTX pulses={result.PulseCount}, abuse={result.AbuseScore}) [{result.Source}]");
                        onThreat?.Invoke(result);
                    }
                    else
                    {
                        // Tallenna Clean-tulos cacheen (ei kutsuta uudelleen TTL:n aikana)
                        _cache[root] = new CacheEntry
                            { Level = ThreatLevel.Clean, Expires = DateTime.Now.AddHours(_cacheTtlHours) };
                    }
                }
                catch (Exception ex) { AppLogger.Log($"[TI] Lookup {root}: {ex.Message}"); }
                finally { _inFlight.TryRemove(root, out _); }
            });
        }

        // ── API-kutsut ────────────────────────────────────────────

        private async Task<ThreatIntelResult> LookupAsync(string domain)
        {
            if (!await AcquireRateSlot().ConfigureAwait(false)) return null;
            Interlocked.Increment(ref _apiCalls);
            _status = $"TI: {_totalQueries} kyselyä, {_threatsFound} uhkaa, {_apiCalls} API-kutsua";

            ThreatIntelResult result = null;

            // 1. AlienVault OTX — domainit
            if (!string.IsNullOrWhiteSpace(_otxApiKey))
                result = await LookupOtxAsync(domain).ConfigureAwait(false);

            // 2. AbuseIPDB — vain jos OTX ei löytänyt tai ei konfiguroitu
            if (result == null && !string.IsNullOrWhiteSpace(_abuseApiKey))
                result = await LookupAbuseIpDbAsync(domain).ConfigureAwait(false);

            return result;
        }

        private async Task<ThreatIntelResult> LookupOtxAsync(string domain)
        {
            try
            {
                string url = $"https://otx.alienvault.com/api/v1/indicators/domain/{Uri.EscapeDataString(domain)}/general";
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.Add("X-OTX-API-KEY", _otxApiKey);

                using var resp = await _http.SendAsync(req).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) return null;

                string body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(body);

                int pulseCount = 0;
                if (doc.RootElement.TryGetProperty("pulse_info", out var pi) &&
                    pi.TryGetProperty("count", out var cnt))
                    pulseCount = cnt.GetInt32();

                ThreatLevel level = pulseCount >= _otxThreshold ? ThreatLevel.Malicious
                                  : pulseCount > 0             ? ThreatLevel.Suspicious
                                                               : ThreatLevel.Clean;
                return new ThreatIntelResult
                {
                    Domain = domain, Level = level,
                    PulseCount = pulseCount, Source = "OTX"
                };
            }
            catch (Exception ex) { AppLogger.Log($"[TI/OTX] {ex.Message}"); return null; }
        }

        private async Task<ThreatIntelResult> LookupAbuseIpDbAsync(string indicator)
        {
            // AbuseIPDB käsittelee vain IP-osoitteita
            // Domainille ei tehdä erillistä DNS-resoluutiota (yksityisyysriski)
            if (!System.Net.IPAddress.TryParse(indicator, out _)) return null;
            try
            {
                string url = $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(indicator)}&maxAgeInDays=90";
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Headers.Add("Key", _abuseApiKey);
                req.Headers.Add("Accept", "application/json");

                using var resp = await _http.SendAsync(req).ConfigureAwait(false);
                if (!resp.IsSuccessStatusCode) return null;

                string body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(body);

                int score = 0;
                if (doc.RootElement.TryGetProperty("data", out var data) &&
                    data.TryGetProperty("abuseConfidenceScore", out var sc))
                    score = sc.GetInt32();

                ThreatLevel level = score >= 80 ? ThreatLevel.Malicious
                                  : score >= _abuseThreshold ? ThreatLevel.Suspicious
                                                             : ThreatLevel.Clean;
                return new ThreatIntelResult
                {
                    Domain = indicator, Level = level,
                    AbuseScore = score, Source = "AbuseIPDB"
                };
            }
            catch (Exception ex) { AppLogger.Log($"[TI/AbuseIPDB] {ex.Message}"); return null; }
        }

        // ── Rate limiter ──────────────────────────────────────────

        private async Task<bool> AcquireRateSlot()
        {
            await _rateSlot.WaitAsync().ConfigureAwait(false);
            try
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (now - _hourWindowStart > 3_600_000) // tunti kulunut
                {
                    _requestsThisHour = 0;
                    _hourWindowStart  = now;
                }
                if (_requestsThisHour >= _maxPerHour)
                {
                    AppLogger.Log($"[TI] Rate limit: {_requestsThisHour}/{_maxPerHour} kyselyä/h");
                    return false;
                }
                _requestsThisHour++;
                return true;
            }
            finally { _rateSlot.Release(); }
        }

        // ── Apufunktiot ───────────────────────────────────────────

        /// <summary>Palauttaa root-domainin: "sub.evil.com" → "evil.com".</summary>
        private static string GetRootDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain)) return domain;
            string[] parts = domain.TrimEnd('.').Split('.');
            return parts.Length >= 2
                ? string.Join(".", parts, parts.Length - 2, 2)
                : domain;
        }

        public (long Queries, long CacheHits, long ApiCalls, long Threats) GetStats()
            => (Interlocked.Read(ref _totalQueries),
                Interlocked.Read(ref _cacheHits),
                Interlocked.Read(ref _apiCalls),
                Interlocked.Read(ref _threatsFound));

        public void Dispose() => _rateSlot.Dispose();
    }
}
