using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Säikeenturvallinen seurantaluokka BSS Load Element -datalle (IE 11).
    /// Pitää kirjaa kunkin AP:n viimeisimmästä raportoidusta kanavakuormasta
    /// ja tarjoaa kanavakohtaisen keskiarvon ChannelAnalyzer.CalcInterference:lle.
    ///
    /// Käyttötapa:
    ///   1) Engine instantioi yhden tämän luokan instanssin elinkaarensa ajaksi.
    ///   2) PassiveScannerin BeaconReceived-tapahtumassa kutsutaan Update().
    ///   3) Kun engine rakentaa analyysisnapshotin, kutsutaan GetPerChannelAverage()
    ///      ja syötetään tuloksena saatu Dictionary ChannelAnalyzer:lle.
    ///   4) Periodisesti (esim. kerran kierroksessa) kutsutaan Prune()
    ///      siivoamaan AP:t joita ei ole nähty pitkään aikaan.
    /// </summary>
    public class ChannelLoadTracker
    {
        private struct Entry
        {
            public int      Channel;
            public int      Utilization;   // 0..100 %
            public int      StationCount;  // -1 = ei tiedossa
            public DateTime UpdatedUtc;
        }

        // Avain = BSSID (case-insensitive)
        private readonly ConcurrentDictionary<string, Entry> _data =
            new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Kirjaa AP:n viimeisimmän raportoidun kanavakuorman.</summary>
        public void Update(string bssid, int channel, int? channelUtilization, int? stationCount = null)
        {
            if (string.IsNullOrEmpty(bssid) || channel <= 0 || !channelUtilization.HasValue)
                return;
            int util = Math.Max(0, Math.Min(100, channelUtilization.Value));
            _data[bssid] = new Entry
            {
                Channel      = channel,
                Utilization  = util,
                StationCount = stationCount ?? -1,
                UpdatedUtc   = DateTime.UtcNow
            };
        }

        /// <summary>
        /// Palauttaa BSSID-kohtaisen kuorma-arvon näkyväksi
        /// (esim. AnalyzedAccessPoint.ChannelUtilization:in täyttöä varten).
        /// </summary>
        public int? GetUtilization(string bssid)
            => bssid != null && _data.TryGetValue(bssid, out var e) ? e.Utilization : (int?)null;

        public int? GetStationCount(string bssid)
        {
            if (bssid != null && _data.TryGetValue(bssid, out var e) && e.StationCount >= 0)
                return e.StationCount;
            return null;
        }

        /// <summary>
        /// Palauttaa kanava → keskimääräinen utilisaatio (0..100 %)
        /// yhdistettynä kaikista samalla kanavalla olevista AP:istä.
        /// Tämä syötetään suoraan ChannelAnalyzer.CalcInterference:lle.
        /// </summary>
        public Dictionary<int, int> GetPerChannelAverage()
        {
            // sums[ch] = (utilisaatioiden summa, näytteiden määrä)
            var sums = new Dictionary<int, (int sum, int count)>();
            foreach (var kv in _data)
            {
                var e = kv.Value;
                if (e.Channel <= 0) continue;
                sums.TryGetValue(e.Channel, out var cur);
                sums[e.Channel] = (cur.sum + e.Utilization, cur.count + 1);
            }
            var result = new Dictionary<int, int>(sums.Count);
            foreach (var kv in sums)
                result[kv.Key] = kv.Value.sum / kv.Value.count;
            return result;
        }

        /// <summary>
        /// Poistaa AP:t joita ei ole nähty maxAge:n sisällä.
        /// Estää näkymättömäksi muuttuneiden AP:iden vaikutuksen kuormalaskentaan.
        /// </summary>
        public int Prune(TimeSpan maxAge)
        {
            var cutoff = DateTime.UtcNow - maxAge;
            int removed = 0;
            foreach (var kv in _data)
            {
                if (kv.Value.UpdatedUtc < cutoff && _data.TryRemove(kv.Key, out _))
                    removed++;
            }
            return removed;
        }

        /// <summary>Tunnettujen BSSID-kuorma-arvojen lukumäärä (diagnostiikka).</summary>
        public int Count => _data.Count;
    }
}
