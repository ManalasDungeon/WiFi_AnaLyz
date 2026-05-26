using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Tunnistaa PMKID-keräilyhyökkäyksen käyttäytymisanalyysin avulla.
    ///
    /// PMKID-hyökkäys (Jens Steube 2018):
    ///   Hyökkääjä lähettää Association Request AP:lle ilman aiempaa yhdistymistä.
    ///   AP vastaa EAPOL-Key Message 1:llä joka sisältää PMKID-tiivisteen.
    ///   Hyökkääjä kerää tiivisteen ja vie sen offline-salasanankrakkaustyökaluille.
    ///
    /// Tunnistusmalli (behavioral, ei kryptografinen):
    ///   Sama MAC-osoite aloittaa EAPOL-kättelyä useammalla kuin 3 eri AP:lla
    ///   alle 60 sekunnissa. Normaali laite käyttelee vain yhtä AP:ta kerrallaan.
    ///   Hyökkääjän työkalu (esim. hcxdumptool) käy läpi kaikki näkyvät AP:t.
    ///
    /// Tärkeä rajoitus:
    ///   Emme parssi EAPOL-Key-kehyksen sisäisiä kryptografisia kenttiä
    ///   (Key Nonce, Key MIC, Key Data, PMKID-arvo). Havaitsemme ainoastaan
    ///   EAPOL-kättelyn käynnistymisen (EtherType 0x888E) ja laskemme
    ///   kohde-AP:t per asiakaslaite. Tämä riittää hyökkäysmallin tunnistamiseen.
    /// </summary>
    public sealed class EapolTracker : IDisposable
    {
        // Hyökkäyskynnysarvot
        private const int  WindowSeconds   = 60;  // seurantaikkuna
        private const int  ApThreshold     = 3;   // eri AP:ta → hälytys

        // Avain = clientMac → jono (aika, bssid) -pareista
        private readonly ConcurrentDictionary<string,
            Queue<(DateTime T, string Bssid)>> _byClient =
            new(StringComparer.OrdinalIgnoreCase);

        // Cooldown: älä hälytä samasta clientista useammin kuin kerran per 10 min
        private readonly ConcurrentDictionary<string, DateTime> _lastAlert =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentQueue<EapolEvent> _events = new();
        private volatile string _status = "EAPOL: odottaa dataa";
        private long _totalFrames;

        public string Status     => _status;
        public long   TotalFrames => Interlocked.Read(ref _totalFrames);

        // ── Datan syöttö ──────────────────────────────────────────

        /// <summary>
        /// Kirjaa uuden EAPOL-kättelyaloituksen.
        /// Kutsutaan PassiveChannelScannerilta kun EtherType 0x888E havaitaan.
        ///
        /// Parametrit:
        ///   clientMac — aloittavan laitteen MAC (Address2 802.11-kehyksessä)
        ///   bssidMac  — kohde-AP:n BSSID (Address3 tai Address1 riippuen suunnasta)
        /// </summary>
        public void RecordEapolFrame(string clientMac, string bssidMac)
        {
            if (string.IsNullOrEmpty(clientMac) || string.IsNullOrEmpty(bssidMac)) return;
            Interlocked.Increment(ref _totalFrames);

            var q = _byClient.GetOrAdd(clientMac,
                _ => new Queue<(DateTime, string)>());

            var now    = DateTime.Now;
            var cutoff = now.AddSeconds(-WindowSeconds);

            lock (q)
            {
                q.Enqueue((now, bssidMac));
                // Siivoa ikkuna
                while (q.Count > 0 && q.Peek().T < cutoff)
                    q.Dequeue();

                // Laske eri AP:t tässä ikkunassa
                int distinctAps = q.Select(e => e.Bssid)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count();

                _status = $"EAPOL: {_byClient.Count} laitetta, " +
                          $"{Interlocked.Read(ref _totalFrames)} kehystä nähty";

                if (distinctAps <= ApThreshold) return;

                // Cooldown-tarkistus
                if (_lastAlert.TryGetValue(clientMac, out var last) &&
                    (now - last).TotalMinutes < 10) return;

                _lastAlert[clientMac] = now;

                var evt = new EapolEvent
                {
                    Time           = now,
                    ClientMac      = clientMac,
                    BssidMac       = bssidMac,
                    IsLikelyAttack = true,
                    HasPmkid       = false, // emme parssi kryptografisia kenttiä
                    Detail         = $"PMKID-keräilymalli: {clientMac} aloitti EAPOL-kättelyn " +
                                     $"{distinctAps} eri AP:n kanssa {WindowSeconds} sekunnissa " +
                                     $"(kynnys {ApThreshold}). Mahdollinen hcxdumptool/hcxtools."
                };

                _events.Enqueue(evt);
            }
        }

        // ── Tulokset ──────────────────────────────────────────────

        /// <summary>Palauttaa uudet hälytyshavainnot ja tyhjentää jonon.</summary>
        public List<EapolEvent> DrainAlerts()
        {
            var list = new List<EapolEvent>();
            while (_events.TryDequeue(out var e)) list.Add(e);
            return list;
        }

        /// <summary>
        /// Palauttaa tilannevedoksen kaikista aktiivisista laitteista
        /// (kättely vähintään 2 eri AP:n kanssa viimeisen 60 s aikana).
        /// Käytetään konsolinäkymässä ja dashboardissa.
        /// </summary>
        public sealed class EapolSummaryEntry
        {
            public string ClientMac  { get; set; }
            public int    DistinctAps { get; set; }
            public bool   Suspicious  { get; set; }
        }

        public List<EapolSummaryEntry> GetSummary()
        {
            var cutoff = DateTime.Now.AddSeconds(-WindowSeconds);
            var result = new List<EapolSummaryEntry>();

            foreach (var kv in _byClient)
            {
                List<(DateTime T, string Bssid)> snapshot;
                lock (kv.Value)
                    snapshot = kv.Value.Where(e => e.T >= cutoff).ToList();

                if (snapshot.Count < 2) continue;
                int distinct = snapshot
                    .Select(e => e.Bssid)
                    .Distinct(StringComparer.OrdinalIgnoreCase).Count();
                if (distinct < 2) continue;
                result.Add(new EapolSummaryEntry
                {
                    ClientMac   = kv.Key,
                    DistinctAps = distinct,
                    Suspicious  = distinct > ApThreshold
                });
            }

            return result.OrderByDescending(r => r.DistinctAps).ToList();
        }

        public void Dispose() { }
    }
}
