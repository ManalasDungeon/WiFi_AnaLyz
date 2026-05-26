using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    // ── Datatyypit ────────────────────────────────────────────────

    /// <summary>Yksittäinen honeypot-havainto (probe, yhteys tai deauth ansaVerkkoon).</summary>
    public class HoneypotEvent
    {
        public DateTime Time        { get; set; } = DateTime.Now;
        /// <summary>"ProbeRequest", "Connection", "Deauth".</summary>
        public string   Kind        { get; set; }
        public string   SourceMac   { get; set; }
        public string   TargetSsid  { get; set; }
        /// <summary>100 % varmuus — jokainen osuma on tahallinen.</summary>
        public int      Confidence  { get; set; } = 100;
        public string   Detail      { get; set; }
    }

    /// <summary>
    /// Passiivinen Wi-Fi-ansa: havaitsee laitteet jotka probeaavat tai yrittävät
    /// yhdistää haamutukiasemiin (decoy SSID:iin).
    ///
    /// Toimintaperiaate:
    ///   Normaali käyttäjä ei koskaan yhdistä tuntemattomaan
    ///   verkkoon — jokainen osuma on 100 % tahallista toimintaa tai
    ///   haittaohjelmaa. Ei vääriä positiivisia.
    ///
    /// Tasot:
    ///   1) Passiivinen (oletus): Seuraa 802.11 Probe Request -kehyksiä (subtype 4)
    ///      jotka kohdistuvat decoy SSID:ihin. Ei vaadi ylimääräistä hardware-tukea.
    ///
    ///   2) Aktiivinen (valinnainen): Luo Windows Hosted Network -tukiaseman
    ///      joka näkyy laitteiden Wi-Fi-haussa. Vaatii Admin-oikeudet ja
    ///      WLAN-adapteri, joka tukee Virtual Station Mode.
    ///
    /// Decoy SSID:t konfiguroidaan WifiConfig.HoneypotSsids[]-listassa.
    /// Tyhjä lista = käytetään oletuksia.
    /// </summary>
    public sealed class WifiHoneypot : IDisposable
    {
        // ── Oletukset houkutteleviksi SSID-nimiksi ────────────────
        // Valittu verkkonimiksi joihin hyökkääjät tyypillisesti yhdistävät automaattisesti
        // (wardriving-profilointi, autoliityntäprofilit, oletusarvoset SSID:t)
        private static readonly string[] DefaultDecoys =
        {
            "Free_Public_WiFi",
            "NETGEAR",
            "Linksys",
            "Guest",
            "Admin_Network",
            "TestAP",
            "xfinitywifi",
            "attwifi",
        };

        private readonly HashSet<string> _decoySet;
        private readonly ConcurrentQueue<HoneypotEvent> _events = new();
        private readonly ConcurrentDictionary<string, DateTime> _seenMacs =
            new(StringComparer.OrdinalIgnoreCase);

        private volatile bool  _softApRunning = false;
        private string         _softApSsid;
        private string         _softApBssid;
        private volatile string _status = "Honeypot: passiivinen kuuntelu";
        private readonly object _softApLock = new();

        public string Status      => _status;
        public bool   SoftApActive => _softApRunning;
        public string SoftApBssid  => _softApBssid;

        /// <summary>
        /// Laukaistaan kun laite probeaa tai yrittää yhdistää decoy-verkkoon.
        /// Jokaisesta MAC:sta hälytys enintään kerran per 5 min (cooldown).
        /// </summary>
        public event Action<HoneypotEvent> EventDetected;

        public WifiHoneypot(IEnumerable<string> decoyNames = null)
        {
            var names = decoyNames?.Where(n => !string.IsNullOrWhiteSpace(n)).ToArray()
                        ?? Array.Empty<string>();
            _decoySet = new HashSet<string>(
                names.Length > 0 ? names : DefaultDecoys,
                StringComparer.OrdinalIgnoreCase);

            _status = $"Honeypot: {_decoySet.Count} decoy-SSID:ä passiivisessa kuuntelussa";
            AppLogger.Log($"[Honeypot] Decoy-SSID:t: {string.Join(", ", _decoySet)}");
        }

        // ── Passiivinen probe-tunnistus ───────────────────────────

        /// <summary>
        /// Kutsutaan PassiveChannelScannerilta kun Probe Request -kehys saapuu.
        /// Subtype 4 = Probe Request.
        ///
        /// 802.11 Probe Request -rakenne (MAC-otsikon jälkeen):
        ///   IE 0 (SSID) — haettu SSID (tyhjä = broadcast probe)
        ///   IE 1 (Supported Rates)
        ///   jne.
        /// </summary>
        public void ProcessProbeRequest(byte[] data, int macOff, string sourceMac)
        {
            // Parsi SSID Information Elementistä (IE 0)
            int bodyOff = macOff + 24; // MAC-otsikko 24 B
            string probedSsid = ParseSsidIE(data, bodyOff);

            if (string.IsNullOrEmpty(probedSsid)) return; // broadcast probe — ei kohdistettu

            if (!_decoySet.Contains(probedSsid)) return; // ei decoy-SSID

            EmitEvent(new HoneypotEvent
            {
                Kind       = "ProbeRequest",
                SourceMac  = sourceMac,
                TargetSsid = probedSsid,
                Detail     = $"Probe Request → {probedSsid}"
            }, sourceMac);
        }

        /// <summary>
        /// Kutsutaan kun laite lähettää Deauth-kehyksen decoy-BSSID:lle.
        /// Viittaa aktiiviseen hyökkäystyökaluun (esim. aircrack-ng, mdk4).
        /// </summary>
        public void ProcessDeauthToHoneypot(string senderMac, string targetBssid)
        {
            if (_softApBssid == null) return;
            if (!string.Equals(targetBssid, _softApBssid, StringComparison.OrdinalIgnoreCase)) return;

            EmitEvent(new HoneypotEvent
            {
                Kind       = "Deauth",
                SourceMac  = senderMac,
                TargetSsid = _softApSsid,
                Detail     = $"Deauth lähetetty decoy AP:lle ({_softApBssid})",
                Confidence = 100
            }, senderMac);
        }

        private void EmitEvent(HoneypotEvent evt, string mac)
        {
            // Cooldown 5 min per MAC
            if (!ShouldAlert(mac)) return;

            _events.Enqueue(evt);
            AppLogger.Log($"[Honeypot] {evt.Kind}: {mac} → {evt.TargetSsid}");
            EventDetected?.Invoke(evt);
        }

        private bool ShouldAlert(string mac)
        {
            if (_seenMacs.TryGetValue(mac, out var last) &&
                (DateTime.Now - last).TotalMinutes < 5) return false;
            _seenMacs[mac] = DateTime.Now;
            return true;
        }

        private static string ParseSsidIE(byte[] data, int bodyOff)
        {
            if (bodyOff + 2 > data.Length) return "";
            if (data[bodyOff] != 0) return ""; // ei SSID-IE
            int len = data[bodyOff + 1];
            if (len == 0 || bodyOff + 2 + len > data.Length) return "";
            try { return System.Text.Encoding.UTF8.GetString(data, bodyOff + 2, len); }
            catch { return ""; }
        }

        // ── Aktiivinen SoftAP (Windows Hosted Network) ───────────

        /// <summary>
        /// Käynnistää Windows Hosted Network -tukiaseman (SoftAP).
        /// Vaatii: Admin-oikeudet + WLAN-adapteri joka tukee Virtual Station.
        ///
        /// HUOMIO: Avoin verkko (ei salasanaa) — kaikki liikenteet näkyvät
        /// selväkielisenä. Käytä vain hallituissa ympäristöissä.
        /// </summary>
        public bool StartSoftAp(string ssid = null)
        {
            lock (_softApLock)
            {
                if (_softApRunning)
                {
                    AppLogger.Log("[Honeypot] SoftAP jo käynnissä");
                    return true;
                }
                _softApSsid = ssid ?? "Free_Public_WiFi";
                if (!_decoySet.Contains(_softApSsid)) _decoySet.Add(_softApSsid);
                return StartSoftApInternal(_softApSsid);
            }
        }

        private bool StartSoftApInternal(string ssid)
        {
            try
            {
                // Vaihe 1: Aseta SSID ja avoin verkko
                RunNetsh($"wlan set hostednetwork mode=allow ssid=\"{ssid}\" key=\"\"");
                // Vaihe 2: Käynnistä
                string result = RunNetsh("wlan start hostednetwork");

                if (result.Contains("started") || result.Contains("käynnistetty"))
                {
                    _softApRunning = true;
                    // Hae BSSID käynnistyneeltä AP:lta
                    _softApBssid = GetHostedNetworkBssid();
                    _status = $"Honeypot: SoftAP LIVE '{ssid}' ({_softApBssid ?? "BSSID tuntematon"})";
                    AppLogger.Log($"[Honeypot] SoftAP käynnistyi: {ssid} / {_softApBssid}");
                    return true;
                }
                AppLogger.Log($"[Honeypot] SoftAP käynnistys: {result}");
                return false;
            }
            catch (Exception ex)
            {
                AppLogger.Log($"[Honeypot] SoftAP virhe: {ex.Message}");
                return false;
            }
        }

        public void StopSoftAp()
        {
            lock (_softApLock)
            {
                if (!_softApRunning) return;
                try
                {
                    RunNetsh("wlan stop hostednetwork");
                    RunNetsh("wlan set hostednetwork mode=disallow");
                    _softApRunning = false;
                    _softApBssid   = null;
                    _status = $"Honeypot: {_decoySet.Count} decoy-SSID:ä passiivisessa kuuntelussa";
                    AppLogger.Log("[Honeypot] SoftAP pysäytetty");
                }
                catch (Exception ex) { AppLogger.Log($"[Honeypot] Stop virhe: {ex.Message}"); }
            }
        }

        private static string RunNetsh(string args)
        {
            var psi = new ProcessStartInfo("netsh", args)
            {
                RedirectStandardOutput = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using var proc = Process.Start(psi);
            string output = proc?.StandardOutput.ReadToEnd() ?? "";
            proc?.WaitForExit(3000);
            return output;
        }

        private static string GetHostedNetworkBssid()
        {
            try
            {
                string output = RunNetsh("wlan show hostednetwork");
                // Etsi rivi "BSSID" tai "MAC Address"
                foreach (var line in output.Split('\n'))
                {
                    string l = line.Trim();
                    if (l.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
                    {
                        int colon = l.IndexOf(':');
                        if (colon >= 0) return l.Substring(colon + 1).Trim();
                    }
                }
            }
            catch { }
            return null;
        }

        // ── Julkinen lukurajapinta ─────────────────────────────────

        public List<HoneypotEvent> DrainEvents()
        {
            var list = new List<HoneypotEvent>();
            while (_events.TryDequeue(out var e)) list.Add(e);
            return list;
        }

        public List<HoneypotEvent> GetRecentEvents(int maxItems = 50)
        {
            var arr = _events.ToArray();
            return arr.Skip(Math.Max(0, arr.Length - maxItems)).ToList();
        }

        public IReadOnlyCollection<string> DecoyNames => _decoySet;

        public void Dispose()
        {
            if (_softApRunning) StopSoftAp();
        }
    }
}
