using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Seuraa Deauthentication (subtype 12) ja Disassociation (subtype 10)
    /// -kehyksiä liukuvalla aikaikkunalla.
    ///
    /// Deauth-myrsky = N+ kehystä per BSSID per aikaikkuna → mahdollinen
    /// WPA-salasanan murtamisyritys (PMKID-kaappaus tai 4-way handshake -kaappaus).
    ///
    /// Broadcast-deauth on erityisen vakava: yksi kehys katkaisee KAIKKIEN
    /// asiakkaiden yhteyden samanaikaisesti.
    ///
    /// Käyttötapa:
    ///   1) PassiveChannelScanner parsii Deauth/Disassoc-kehykset ja kutsuu Record().
    ///   2) WifiAnalyzerEngine tarkistaa GetStorm()-palautteet ja lisää hälytykset.
    /// </summary>
    public class DeauthTracker
    {
        // Liukuvan ikkunan parametrit
        private const int WindowSeconds   = 10;  // seurantaikkuna
        private const int StormThreshold  = 5;   // tähän hälytetään
        private const int BroadcastAlertN = 2;   // broadcast-deauth on heti epäilyttävä

        // Avain = BSSID (lähettäjä)
        private readonly ConcurrentDictionary<string, Queue<DeauthEvent>> _byBssid =
            new(StringComparer.OrdinalIgnoreCase);

        // Broadcast-erityisseuranta: broadcast voi kohdistua useaan AP:hen
        private readonly ConcurrentDictionary<string, int> _broadcastCount =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly object _lock = new();

        // Reason Code -käännöstaulu (802.11-2020 §9.4.1.7, yleisimmät)
        private static readonly Dictionary<ushort, string> ReasonCodes = new()
        {
            {  1, "Unspecified" },
            {  2, "Previous auth no longer valid" },
            {  3, "Deauth: leaving BSS" },
            {  4, "Inactivity" },
            {  5, "AP capacity reached" },
            {  6, "Class 2 from non-authed STA" },
            {  7, "Class 3 from non-assoc STA" },
            {  8, "Disassoc: leaving BSS" },
            {  9, "Not authed with this STA" },
            { 15, "4-way handshake timeout" },
            { 16, "Group key update timeout" },
            { 17, "IE mismatch (RSNA)" },
            { 23, "IEEE 802.1X auth failed" },
        };

        /// <summary>
        /// Kirjaa uuden Deauth- tai Disassoc-kehyksen.
        /// Kutsutaan PassiveChannelScannerin parsimasta kehyksestä.
        /// </summary>
        public void Record(DeauthEvent evt)
        {
            if (evt == null || string.IsNullOrEmpty(evt.SenderBssid)) return;

            lock (_lock)
            {
                if (!_byBssid.TryGetValue(evt.SenderBssid, out var q))
                {
                    q = new Queue<DeauthEvent>(64);
                    _byBssid[evt.SenderBssid] = q;
                }
                q.Enqueue(evt);

                if (evt.IsBroadcast)
                    _broadcastCount.AddOrUpdate(evt.SenderBssid, 1, (_, c) => c + 1);

                // Siivoa vanhentuneet kehykset O(n) ikkunan alusta
                var cutoff = DateTime.Now.AddSeconds(-WindowSeconds);
                while (q.Count > 0 && q.Peek().Time < cutoff)
                    q.Dequeue();
            }
        }

        /// <summary>
        /// Tarkistaa onko deauth-myrsky aktiivisena jollakin BSSID:llä.
        /// Palauttaa listan hälytyksistä jotka on käsiteltävä.
        /// Nollaa palautettujen kohteiden laskurit.
        /// </summary>
        public List<(string Bssid, string Message, bool IsBroadcast)> DrainAlerts()
        {
            var result = new List<(string, string, bool)>();
            var cutoff = DateTime.Now.AddSeconds(-WindowSeconds);

            lock (_lock)
            {
                foreach (var kv in _byBssid.ToList())
                {
                    var q = kv.Value;
                    // Siivoa ikkuna
                    while (q.Count > 0 && q.Peek().Time < cutoff)
                        q.Dequeue();
                    if (q.Count == 0) continue;

                    var frames    = q.ToList();
                    int total     = frames.Count;
                    int bcast     = frames.Count(f => f.IsBroadcast);
                    int deauths   = frames.Count(f => f.IsDeauth);
                    int disassocs = total - deauths;

                    bool storm = total >= StormThreshold;
                    bool bcastStorm = bcast >= BroadcastAlertN;

                    if (!storm && !bcastStorm) continue;

                    // Reason code -jakaumasta voi päätellä hyökkäystyyppiä
                    var topReason = frames
                        .GroupBy(f => f.ReasonCode)
                        .OrderByDescending(g => g.Count())
                        .FirstOrDefault();
                    string reasonInfo = topReason != null
                        ? $" Reason {topReason.Key}" +
                          (ReasonCodes.TryGetValue(topReason.Key, out var rt) ? $" ({rt})" : "")
                        : "";

                    string msg = bcastStorm
                        ? $"BROADCAST Deauth-myrsky: {bcast} broadcast-kehystä {WindowSeconds} s " +
                          $"— kaikki asiakkaat irrotettiin!{reasonInfo}"
                        : $"Deauth-myrsky: {total} kehystä {WindowSeconds} s " +
                          $"(Deauth {deauths}, Disassoc {disassocs}){reasonInfo} " +
                          $"— mahdollinen WPA-kaapatuyritys";

                    // ── PMF-ristikäyttö ───────────────────────────────────
                    // Jos BSSID tukee PMF mutta deauth on salaamaton → VARMENNETTU HYÖKKÄYS.
                    // Oikea PMF-tukeva AP lähettää aina salatun Management Frame.
                    bool hasPmf = _pmfByBssid.TryGetValue(kv.Key, out var pmf);
                    bool hasUnprotected = frames.Any(f => !f.IsFrameProtected);

                    string pmfTag = "";
                    if (hasPmf && hasUnprotected)
                    {
                        pmfTag = pmf.Required
                            ? " *** VARMENNETTU HYÖKKÄYS: MFPR=1 mutta kehykset salaamattomia! ***"
                            : " *** TODENNÄKÖINEN HYÖKKÄYS: MFPC=1 mutta kehykset salaamattomia! ***";
                    }

                    // ── Reason Code -hyökkäystunnistus ───────────────────────
                    // Hyökkäystyökalut (aireplay-ng, mdk3/mdk4, wifijammer) käyttävät
                    // oletuksena reason codeja 1 (Unspecified) tai 7 (Class 3 frame).
                    // Täysin homogeeninen reason code -jakauma = automatisoitu hyökäys.
                    string reasonTag = "";
                    var reasonGroups = frames.GroupBy(f => f.ReasonCode).ToList();
                    if (reasonGroups.Count == 1)
                    {
                        ushort singleCode = reasonGroups[0].Key;
                        string toolHint = singleCode switch
                        {
                            1  => "aireplay-ng/mdk oletusarvo",
                            7  => "aireplay-ng -0 / wifijammer tyypillinen",
                            4  => "mdk3/mdk4 tyypillinen",
                            _  => null
                        };
                        if (toolHint != null)
                            reasonTag = $" [Reason {singleCode} = {toolHint}]";
                    }

                    result.Add((kv.Key, msg + pmfTag + reasonTag, bcastStorm || (hasPmf && hasUnprotected)));

                    // Nollaa jotta sama myrsky ei hälytä joka kierroksella
                    q.Clear();
                    _broadcastCount.TryRemove(kv.Key, out _);
                }
            }
            return result;
        }

        /// <summary>
        /// Palauttaa viimeisin 60 s DeauthEvent-lista kaikilta BSSID:ltä.
        /// Käytetään konsolinäkymän ja dashboardin raportointiin.
        /// </summary>
        public List<DeauthEvent> GetRecentEvents(int maxSeconds = 60)
        {
            var cutoff = DateTime.Now.AddSeconds(-maxSeconds);
            var result = new List<DeauthEvent>();
            lock (_lock)
            {
                foreach (var q in _byBssid.Values)
                    result.AddRange(q.Where(e => e.Time >= cutoff));
            }
            return result.OrderByDescending(e => e.Time).Take(50).ToList();
        }

        public int TotalEventCount
        {
            get { lock (_lock) return _byBssid.Values.Sum(q => q.Count); }
        }

        /// <summary>Parsii Reason Code -tavut kehyksestä ja palauttaa DeauthEvent:in.</summary>
        public static DeauthEvent ParseFrame(
            byte[] data, int macOff, string senderBssid,
            string targetMac, bool isDeauth, DateTime ts,
            bool isFrameProtected = false)
        {
            ushort reason = 0;
            // Reason code: 2 tavua MAC-otsikon (24 B) jälkeen kehysrungossa
            int reasonOff = macOff + 24;
            if (data.Length >= reasonOff + 2)
                reason = (ushort)(data[reasonOff] | (data[reasonOff + 1] << 8));

            ReasonCodes.TryGetValue(reason, out string reasonText);
            return new DeauthEvent
            {
                Time             = ts,
                SenderBssid      = senderBssid,
                TargetMac        = targetMac,
                IsDeauth         = isDeauth,
                ReasonCode       = reason,
                ReasonText       = reasonText ?? $"Reason {reason}",
                IsBroadcast      = string.Equals(targetMac, "FF:FF:FF:FF:FF:FF",
                                       StringComparison.OrdinalIgnoreCase),
                IsFrameProtected = isFrameProtected
            };
        }

        // ── PMF-tietokanta ────────────────────────────────────────

        // Rekisteröidyt PMF-kyvykkyydet: BSSID → (PmfCapable, PmfRequired)
        private readonly ConcurrentDictionary<string, (bool Capable, bool Required)> _pmfByBssid =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Päivittää BSSID:n PMF-kyvykkyyden kun Beacon-kehys on parsittu.
        /// Kutsutaan WifiAnalyzerEngine.AttachPassiveScannerEvents:sta.
        /// </summary>
        public void UpdatePmf(string bssid, bool pmfCapable, bool pmfRequired)
        {
            if (!string.IsNullOrEmpty(bssid) && (pmfCapable || pmfRequired))
                _pmfByBssid[bssid] = (pmfCapable, pmfRequired);
        }
    }
}
