using System;
using System.Collections.Generic;
using System.Linq;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Kanava-analyysi: pisteytyslaskenta, kanavakuorma, tuntikohtainen häiriöseuranta.
    /// </summary>
    public class ChannelAnalyzer
    {
        private const int OverlapRange24G    = 4;
        private const int OverlapRange5GPlus = 1;

        private readonly Dictionary<int, Queue<double>> _hourlyInterference = new();
        private readonly object                        _hourlyLock          = new();

        private readonly double _coChannelWeight;
        private readonly double _adjacentWeight;

        public ChannelAnalyzer(WifiConfig cfg)
        {
            _coChannelWeight = cfg.CoChannelPenaltyWeight;
            _adjacentWeight  = cfg.AdjacentPenaltyWeight;
        }

        // ── Pisteytys ─────────────────────────────────────────────

        /// <summary>
        /// Laskee co-channel- ja adjacent-overlap-määrät sekä kokonaispenaltyn.
        ///
        /// KORJAUS: Aiempi versio käytti beacon-intervallia kanavakuorman approksimointiin.
        /// Beacon-intervalli on AP:n staattinen asetus (oletus 100 TU = 102.4 ms), eikä
        /// se mittaa kanavan käyttöastetta. Oikea mittari on BSS Load Element (IE 11),
        /// joka sisältää ChannelUtilization-tavun (0..255 → 0..100 %).
        /// Jos PassiveChannelScanner toimittaa BSS Load -datan, käytä sitä kuormakertoimena.
        /// </summary>
        public (int co, int adj, double penalty) CalcInterference(
            int channel,
            Dictionary<int, int> chCounts,
            Dictionary<int, int> channelUtilizationByChannel = null)
        {
            if (channel <= 0) return (0, 0, 0);
            int range = channel <= 14 ? OverlapRange24G : OverlapRange5GPlus;

            chCounts.TryGetValue(channel, out int same);
            int co = Math.Max(0, same - 1);

            int adj = 0;
            for (int d = -range; d <= range; d++)
            {
                int ch2 = channel + d;
                if (ch2 <= 0 || ch2 == channel) continue;
                if (chCounts.TryGetValue(ch2, out int cc)) adj += cc;
            }

            double penalty = co * _coChannelWeight + adj * _adjacentWeight;

            // ── Todellinen kanavankäyttöaste (BSS Load IE 11) ─────────
            // Jos saatavilla, käytä sitä lineaarisena kertoimena: 0 % = 1.0, 100 % = 2.0
            if (channelUtilizationByChannel != null && penalty > 0 &&
                channelUtilizationByChannel.TryGetValue(channel, out int util))
            {
                double factor = 1.0 + Math.Min(1.0, util / 100.0);
                penalty *= factor;
            }

            return (co, adj, Math.Round(penalty, 2));
        }

        // ── Kaistantunnistus ──────────────────────────────────────

        /// <summary>
        /// KORJAUS: Pelkkä kanavanumero ei riitä erottamaan 2.4 GHz:tä ja 6 GHz:tä,
        /// koska Wi-Fi 6E:n kanavanumerointi (1, 5, 9, …, 233) menee päällekkäin
        /// 2.4 GHz:n (1–14) kanssa. Aiempi versio luokitteli 6 GHz kanavat 1, 5, 9, 13
        /// virheellisesti 2.4 GHz:ksi.
        ///
        /// Korjaus: jos kutsuja toimittaa frequencyMhz:n, päätös on yksikäsitteinen.
        /// Ilman frekvenssitietoa palautetaan "?" niissä rajatapauksissa joissa kanava
        /// voi kuulua useaan kaistaan.
        /// </summary>
        public static string PhyToBand(string phy, int channel, int frequencyMhz = 0)
        {
            // 1) Frekvenssi on yksikäsitteinen, jos saatavilla
            if (frequencyMhz > 0)
            {
                if (frequencyMhz >= 2400 && frequencyMhz < 2500) return "2.4 GHz";
                if (frequencyMhz >= 5000 && frequencyMhz < 5900) return "5 GHz";
                if (frequencyMhz >= 5925 && frequencyMhz < 7125) return "6 GHz";
            }

            // 2) 5 GHz on aina kanavavälillä 36–177
            if (channel >= 36 && channel <= 177) return "5 GHz";

            string p = (phy ?? "").ToUpperInvariant();
            bool isHighEnd = p.Contains("BE") || p.Contains("AX");

            // 3) 6 GHz: kanavat välillä 15–35 (eivät ole valideja 2.4 GHz:llä)
            //    tai > 177 yhdessä Wi-Fi 6E/7 PHY:n kanssa.
            if (isHighEnd)
            {
                if (channel > 14 && channel < 36) return "6 GHz";
                if (channel > 177 && channel <= 233) return "6 GHz";
            }

            // 4) 2.4 GHz:n kanavat 1–14
            //    HUOM: 6 GHz:n kanavat 1, 5, 9, 13 ovat erottamattomissa 2.4 GHz:stä
            //    ilman frekvenssitietoa. Tämä on järjestelmän rajoitus, ei bugi.
            if (channel >= 1 && channel <= 14) return "2.4 GHz";

            return "?";
        }

        // ── Paras 2.4 GHz kanava ─────────────────────────────────

        public static string CalcBestChannel2G(Dictionary<int, int> chCounts, HashSet<int> wideChannels)
        {
            int[] preferred = { 1, 6, 11 };
            int best = preferred.OrderBy(c =>
            {
                chCounts.TryGetValue(c, out int direct);
                int range   = wideChannels.Contains(c) ? 5 : OverlapRange24G;
                int overlap = 0;
                for (int d = -range; d <= range; d++)
                {
                    if (d == 0) continue;
                    if (chCounts.TryGetValue(c + d, out int n)) overlap += n;
                }
                return direct * 3 + overlap;
            }).First();
            chCounts.TryGetValue(best, out int load);
            string wide = wideChannels.Contains(best) ? " 40MHz" : "";
            return load == 0 ? $"{best}{wide} (vapaa)" : $"{best}{wide} ({load} verkko/ja)";
        }

        // ── Tuntikohtainen häiriöseuranta ─────────────────────────

        public void UpdateHourlyInterference(List<AnalyzedAccessPoint> aps)
        {
            int    h     = DateTime.Now.Hour;
            double total = aps.Sum(a => a.InterferencePenalty);
            lock (_hourlyLock)
            {
                if (!_hourlyInterference.ContainsKey(h))
                    _hourlyInterference[h] = new Queue<double>(64);
                _hourlyInterference[h].Enqueue(total);
                if (_hourlyInterference[h].Count > 60)
                    _hourlyInterference[h].Dequeue();  // O(1)
            }
        }

        public List<HourlyInterference> GetHourlyStats()
        {
            var result = new List<HourlyInterference>();
            lock (_hourlyLock)
            {
                for (int h = 0; h < 24; h++)
                {
                    if (!_hourlyInterference.TryGetValue(h, out var vals) || vals.Count == 0) continue;
                    double sum = 0, max = 0;
                    foreach (var v in vals) { sum += v; if (v > max) max = v; }
                    result.Add(new HourlyInterference
                    {
                        Hour        = h,
                        AvgPenalty  = Math.Round(sum / vals.Count, 1),
                        MaxPenalty  = Math.Round(max, 1),
                        SampleCount = vals.Count
                    });
                }
            }
            return result;
        }

        // ── Apufunktiot ───────────────────────────────────────────

        public static string RssiToGrade(int rssi)
        {
            if (rssi >= -50) return "A";
            if (rssi >= -60) return "B";
            if (rssi >= -70) return "C";
            if (rssi >= -80) return "D";
            return                  "F";
        }

        public static string JitterToTag(double j)
            => j < 2.0 ? "Vakaa" : j < 5.0 ? "Normaali" : j < 9.0 ? "Epävakaa" : "Vaihteleva";
    }
}
