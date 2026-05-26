using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Hallinnoi hälytyksiä: cooldown, hystereesi, lokitus ja webhook.
    /// </summary>
    public class AlertManager
    {
        // KORJAUS: Ei enää readonly WifiConfig — kentät ovat volatile/lukittuja
        // jotta ApplyConfig() toimii säikeenturvallisesti hot-reloadin yhteydessä.
        private volatile int    _cooldownSeconds;
        private volatile string _alertLogPath;
        private volatile string _alertWebhookUrl;
        // SuppressedAlertTypes on List<string> alkuperäisessä konfiguraatiossa —
        // kopioidaan HashSet:iksi joka on nopeampi Contains-kutsuihin.
        private readonly HashSet<string> _suppressedTypes = new(StringComparer.OrdinalIgnoreCase);
        private readonly object          _suppressedLock  = new();

        private readonly List<AlertEntry> _alerts    = new();
        private readonly object           _alertLock = new();

        // Cooldown: avain = "Tyyppi:BSSID"
        private readonly Dictionary<string, DateTime> _lastAlertTime = new(StringComparer.OrdinalIgnoreCase);
        private readonly object                       _alertTimeLock = new();
        private int                                   _alertCallCount;

        // Hystereesi: heikon signaalin tila per BSSID
        private readonly HashSet<string> _weakSignalBssids = new(StringComparer.OrdinalIgnoreCase);
        private readonly object          _weakLock         = new();

        // KORJAUS: oma lukko hälytyslokitiedostolle, ettei samanaikaiset hälytykset
        // korruptoi File.AppendAllText-kirjoitusta.
        private readonly object _logFileLock = new();

        private const int MaxAlerts = 500;

        private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };

        public AlertManager(WifiConfig cfg) => ApplyConfig(cfg);

        /// <summary>
        /// Soveltaa uuden konfiguraation lennossa (hot-reload).
        /// Kaikki kenttäpäivitykset ovat säikeenturvallisia:
        ///   - volatile string/int: kirjoitus on atomiinen 64-bittisillä alustoilla
        ///   - SuppressedAlertTypes: päivitetään _suppressedLock:in alla
        /// </summary>
        public void ApplyConfig(WifiConfig cfg)
        {
            if (cfg == null) return;
            _cooldownSeconds = cfg.AlertCooldownSeconds;
            _alertLogPath    = string.IsNullOrWhiteSpace(cfg.AlertLogPath)
                ? "alerts.log" : cfg.AlertLogPath;
            _alertWebhookUrl = cfg.AlertWebhookUrl ?? "";
            lock (_suppressedLock)
            {
                _suppressedTypes.Clear();
                if (cfg.SuppressedAlertTypes != null)
                    foreach (var t in cfg.SuppressedAlertTypes)
                        if (!string.IsNullOrWhiteSpace(t)) _suppressedTypes.Add(t);
            }
        }

        public void Add(string type, string bssid, string message)
        {
            lock (_suppressedLock)
                if (_suppressedTypes.Contains(type ?? "")) return;
            if (!ShouldAlert(type, bssid)) return;

            var entry = new AlertEntry { Time = DateTime.Now, Type = type, Bssid = bssid, Message = message };

            lock (_alertLock)
            {
                _alerts.Add(entry);
                if (_alerts.Count > MaxAlerts) _alerts.RemoveAt(0);
            }

            WriteAlertLog(entry);
            FireWebhookAsync(entry);
        }

        /// <summary>Palauttaa kopion hälytyksistä muokattavana listana.</summary>
        public List<AlertEntry> GetAll() { lock (_alertLock) return new List<AlertEntry>(_alerts); }

        /// <summary>Palauttaa read-only snapshot (ei kopioi listan sisältöä uudelleen).</summary>
        public IReadOnlyList<AlertEntry> Snapshot() { lock (_alertLock) return _alerts.ToArray(); }

        // ── Hystereesi ────────────────────────────────────────────

        public bool IsWeakSignal(string bssid)
        {
            lock (_weakLock) return _weakSignalBssids.Contains(bssid);
        }

        public void SetWeakSignal(string bssid, bool weak)
        {
            lock (_weakLock)
            {
                if (weak) _weakSignalBssids.Add(bssid);
                else      _weakSignalBssids.Remove(bssid);
            }
        }

        // ── Yksityiset apufunktiot ────────────────────────────────

        private bool ShouldAlert(string type, string bssid)
        {
            int cooldown = _cooldownSeconds;
            if (cooldown <= 0) return true;

            string key = $"{type}:{bssid ?? ""}";
            lock (_alertTimeLock)
            {
                if (_lastAlertTime.TryGetValue(key, out var last) &&
                    (DateTime.Now - last).TotalSeconds < cooldown)
                    return false;

                _lastAlertTime[key] = DateTime.Now;

                // Siivoa vanhentuneet merkinnät joka 100. kutsu — ei O(n) per hälytys
                if ((++_alertCallCount % 100) == 0)
                {
                    var cutoff = DateTime.Now.AddSeconds(-(cooldown * 2.0));
                    var stale  = _lastAlertTime
                        .Where(kv => kv.Value < cutoff)
                        .Select(kv => kv.Key).ToList();
                    foreach (var k in stale) _lastAlertTime.Remove(k);
                }
                return true;
            }
        }

        /// <summary>
        /// KORJAUS: lukko tiedostokirjoituksen ympärillä — samanaikaiset hälytykset
        /// eivät enää korruptoi alerts.log:ia. AppLogger:iin jää kompakti rivi,
        /// ja erillinen alerts.log saa tarkan aikaleiman + kentät.
        /// </summary>
        private void WriteAlertLog(AlertEntry a)
        {
            AppLogger.Log($"[ALERT] [{a.Type}] {a.Bssid ?? "-"} — {a.Message}");

            string path = _alertLogPath;
            try
            {
                lock (_logFileLock)
                    System.IO.File.AppendAllText(path,
                        $"[{a.Time:yyyy-MM-dd HH:mm:ss}] [{a.Type}] {a.Bssid ?? "-"} — {a.Message}\r\n",
                        Encoding.UTF8);
            }
            catch (Exception ex) { AppLogger.Log($"[Alert] Lokitus: {ex.Message}"); }
        }

        private void FireWebhookAsync(AlertEntry a)
        {
            string url = _alertWebhookUrl;
            if (string.IsNullOrWhiteSpace(url)) return;
            Task.Run(async () =>
            {
                try
                {
                    string json = JsonSerializer.Serialize(new
                    {
                        ts      = a.Time.ToString("o"),
                        type    = a.Type,
                        bssid   = a.Bssid,
                        message = a.Message
                    });
                    using var content = new StringContent(json, Encoding.UTF8, "application/json");
                    using var resp    = await _http.PostAsync(url, content).ConfigureAwait(false);
                    if (!resp.IsSuccessStatusCode)
                        AppLogger.Log($"[Webhook] HTTP {(int)resp.StatusCode}");
                }
                catch (Exception ex) { AppLogger.Log($"[Webhook] {ex.Message}"); }
            });
        }

        // ── Staattinen apufunktio ─────────────────────────────────

        /// <summary>
        /// KORJAUS: WEP saa nyt erillisen tason 1 (sama kuin WPA, koska molemmat ovat
        /// rikottavia mutta turvallisempia kuin Open). Aiemmin WEP putosi tasolle 0.
        /// </summary>
        public static bool IsSecurityDowngrade(string oldSec, string newSec)
        {
            if (string.IsNullOrEmpty(oldSec) || string.IsNullOrEmpty(newSec)) return false;
            return Level(newSec) < Level(oldSec);
        }

        private static int Level(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            if (s.Contains("3"))   return 4;   // WPA3 (myös "WPA2/3")
            if (s.Contains("Ent")) return 3;   // WPA2-Enterprise
            if (s.Contains("2"))   return 2;   // WPA2
            if (s == "WPA")        return 1;
            if (s == "WEP")        return 1;   // KORJAUS: WEP > Open
            return 0;                          // Open / tuntematon
        }

        /// <summary>
        /// Tarkistaa onko MAC locally administered -bitti asetettu (satunnaistettu MAC).
        /// Android/iOS käyttää satunnaistettuja MAC-osoitteita — ei hälytetä Evil Twiniä.
        /// </summary>
        public static bool IsMacRandomized(string bssid)
        {
            if (string.IsNullOrWhiteSpace(bssid) || bssid.Length < 2) return false;
            try
            {
                // Ensimmäinen oktetti: locally administered -bitti = bit 1 (0x02)
                string firstOctet = bssid.Split(':')[0].Replace("-", "");
                int b = Convert.ToInt32(firstOctet, 16);
                return (b & 0x02) != 0;
            }
            catch { return false; }
        }
    }
}
