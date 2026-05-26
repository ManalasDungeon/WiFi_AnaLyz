using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Kaikki ASCII-kaaviopiirto: signaalihistoria, kanavakuorma, päivärytmi,
    /// spektrianalyysi (uusi).
    /// </summary>
    public static class SignalChartRenderer
    {
        private static readonly char[] _blocks = { ' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█' };

        // ── Signaalihistoria (pystysuuntainen waveform) ───────────

        public static string[] GetSignalChart(
            SignalStats stats, string bssid, BeaconInfo beacon, int width = 50)
        {
            if (stats == null || stats.Count < 2)
                return new[] { "  (ei tarpeeksi historiaa)" };

            var pts   = stats.GetHistory();
            int count = Math.Min(pts.Length, width);
            var slice = new SignalPoint[count];
            Array.Copy(pts, pts.Length - count, slice, 0, count);

            const int minR = -100, maxR = -30, rows = 6;
            int range  = maxR - minR;
            var lines  = new List<string>();
            lines.Add($"  Signaalihistoria: {slice.Length} mittausta | BSSID: {bssid}");
            lines.Add("  " + new string('─', width + 10));

            for (int r = rows - 1; r >= 0; r--)
            {
                int hi = minR + (int)((r + 1) * (range / (double)rows));
                int lo = minR + (int)(r * (range / (double)rows));
                var sb = new StringBuilder();
                sb.Append($"{hi,5} |");
                foreach (var pt in slice)
                {
                    double fill = Math.Max(0, Math.Min(1, (pt.Rssi - lo) / (double)(hi - lo)));
                    sb.Append(_blocks[(int)(fill * (_blocks.Length - 1))]);
                }
                lines.Add("  " + sb);
            }
            lines.Add($"  {minR,5} |{new string('─', count)}");
            if (beacon != null)
                lines.Add($"  Beacon: {beacon.IntervalTu} TU ({beacon.IntervalMs:F1} ms) — {beacon.LoadTag}");
            return lines.ToArray();
        }

        // ── Päivärytmi ─────────────────────────────────────────────

        public static string[] GetDailyRhythmChart(
            List<HourlyInterference> stats, int barWidth = 20)
        {
            if (stats == null || stats.Count == 0)
                return new[] { "  (ei päivärytmidataa vielä)" };

            double maxAvg = stats.Max(s => s.AvgPenalty);
            if (maxAvg <= 0) maxAvg = 1;

            var lines = new List<string>();
            lines.Add("  Päivärytmi — tuntikohtainen häiriö:");
            lines.Add("  " + new string('─', barWidth + 16));
            foreach (var s in stats)
            {
                int len  = Math.Max(s.AvgPenalty > 0 ? 1 : 0, (int)((s.AvgPenalty / maxAvg) * barWidth));
                string w = s.MaxPenalty > maxAvg * 0.8 ? " ⚠" : "  ";
                lines.Add($"  {s.Hour,2}:00 {new string('█', len)}{new string('░', barWidth - len)} {s.AvgPenalty:F0}{w}");
            }
            lines.Add("  " + new string('─', barWidth + 16));
            return lines.ToArray();
        }

        // ── Kanavakuorma (pylväsdiagrammi) ────────────────────────

        public static string[] GetChannelChart(
            List<AnalyzedAccessPoint> aps, int barWidth = 20)
        {
            if (aps == null || aps.Count == 0) return new[] { "  (ei verkkoja)" };

            var chG = new Dictionary<int, int>();
            foreach (var ap in aps)
            {
                if (ap.Channel <= 0) continue;
                chG.TryGetValue(ap.Channel, out int c);
                chG[ap.Channel] = c + 1;
            }
            if (chG.Count == 0) return new[] { "  (ei kanavia)" };
            int maxC = chG.Values.Max();

            var lines = new List<string>();
            lines.Add("  Kanavakuorma:");
            lines.Add("  " + new string('─', barWidth + 22));
            foreach (int ch in chG.Keys.OrderBy(x => x))
            {
                int cnt  = chG[ch];
                int len  = maxC > 0 ? Math.Max(cnt > 0 ? 1 : 0, cnt * barWidth / maxC) : 0;
                string band = ch <= 14 ? "2.4G" : ch <= 177 ? " 5G " : " 6G ";
                string warn = cnt >= 4 ? " ⚠" : cnt >= 2 ? " ·" : "  ";
                lines.Add($"  CH{ch,3} [{band}] {new string('█', len)}{new string('░', barWidth - len)} {cnt,2} AP{warn}");
            }
            lines.Add("  " + new string('─', barWidth + 22));
            return lines.ToArray();
        }

        // ── Spektrianalyysi (uusi) ────────────────────────────────
        // Näyttää kunkin AP:n signaalivahvuuden visuaalisesti oikealla kanavalla,
        // mukaan lukien 40 MHz -kaistanleveyden päällekkäisyys.

        public static string[] GetSpectrumChart(
            List<AnalyzedAccessPoint> aps, int width = 60)
        {
            if (aps == null || aps.Count == 0) return new[] { "  (ei verkkoja)" };

            var by24G = aps.Where(a => a.Channel >= 1  && a.Channel <= 14).OrderBy(a => a.Channel).ToList();
            var by5G  = aps.Where(a => a.Channel >= 36 && a.Channel <= 177).OrderBy(a => a.Channel).ToList();
            var by6G  = aps.Where(a => a.Band == "6 GHz").OrderBy(a => a.Channel).ToList();

            var lines = new List<string>();
            if (by24G.Count > 0) { lines.Add("  2.4 GHz spektri:"); lines.AddRange(Band24Spectrum(by24G, width)); }
            if (by5G.Count  > 0) { lines.Add("  5 GHz kanavakartta:");  lines.AddRange(BandNSpectrum(by5G,  width)); }
            if (by6G.Count  > 0) { lines.Add("  6 GHz kanavakartta:");  lines.AddRange(BandNSpectrum(by6G,  width)); }
            return lines.ToArray();
        }

        private static IEnumerable<string> Band24Spectrum(
            List<AnalyzedAccessPoint> aps, int width)
        {
            // Kanavat 1–13, jokainen vie width/13 merkkiä
            int slots  = 13;
            int colW   = Math.Max(4, width / slots);
            var lines  = new List<string>();

            // Piirretään jokainen AP omalle rivilleen visuaalisena kanavana
            int apCount = Math.Min(aps.Count, 8);
            for (int i = 0; i < apCount; i++)
            {
                var ap    = aps[i];
                int ch    = Math.Max(1, Math.Min(13, ap.Channel));
                bool wide = ap.Phy != null &&
                    (ap.Phy.ToUpperInvariant().Contains("N") || ap.Phy.ToUpperInvariant().Contains("AC"));
                int span  = wide ? 4 : 2;                 // 40 MHz ≈ ±4 kanavaa, 20 MHz ≈ ±2

                string ssid   = FitStr(ap.Ssid ?? "?", 14);
                string rssiS  = $"{ap.Rssi,4} dBm";
                double strength = Math.Max(0, Math.Min(1, (ap.Rssi + 100) / 70.0));
                char   barCh  = strength > 0.7 ? '█' : strength > 0.4 ? '▆' : strength > 0.2 ? '▄' : '▂';

                var sb = new StringBuilder();
                sb.Append("  ");
                for (int c = 1; c <= slots; c++)
                {
                    bool inRange = Math.Abs(c - ch) <= span;
                    bool isCenter = c == ch;
                    if (isCenter) sb.Append(new string(barCh, Math.Max(1, colW - 1)) + " ");
                    else if (inRange) sb.Append(new string('░', Math.Max(1, colW - 1)) + " ");
                    else sb.Append(new string(' ', colW));
                }
                lines.Add($"  {ssid} {rssiS} CH{ch,2}" );
                lines.Add("  " + sb.ToString().TrimEnd());
            }

            // Kanavaviiva
            var ruler = new StringBuilder("  ");
            for (int c = 1; c <= slots; c++)
                ruler.Append((c % 3 == 1 ? $"{c,-3}" : "   ").PadRight(colW));
            lines.Add("  " + new string('─', slots * colW));
            lines.Add(ruler.ToString());
            return lines;
        }

        private static IEnumerable<string> BandNSpectrum(
            List<AnalyzedAccessPoint> aps, int width)
        {
            int show  = Math.Min(aps.Count, 10);
            var lines = new List<string>();
            int barW  = Math.Max(10, width - 30);

            foreach (var ap in aps.Take(show))
            {
                double fill   = Math.Max(0, Math.Min(1, (ap.Rssi + 100) / 70.0));
                int    filled = (int)(fill * barW);
                string ssid   = FitStr(ap.Ssid ?? "?", 12);
                string grade  = ap.Grade ?? "?";
                lines.Add($"  CH{ap.Channel,4} {ssid} {new string('█', filled)}{new string('░', barW - filled)} {ap.Rssi,4} dBm [{grade}]");
            }
            lines.Add("  " + new string('─', width));
            return lines;
        }

        // ── KORJAUS: GetPingChart palautti monirivisen merkkijonon yhdessä alkiossa ──

        public static string[] GetPingChart(
            IEnumerable<SpeedSample> samples, int width = 40)
        {
            var all = new List<SpeedSample>(samples);
            if (all.Count < 2) return new[] { "  (ei tarpeeksi dataa)" };

            double maxPing = all.Max(s => s.PingMs);
            if (maxPing <= 0) maxPing = 1;

            var lines = new List<string>();
            lines.Add($"  Ping-historia ({all.Count} mittausta, max {maxPing:F0} ms):");
            lines.Add("  " + new string('─', width + 10));

            // KORJAUS: Jokainen piste omalle alkiolle — ei StringBuilder.ToString() yhdelle
            foreach (var s in all)
            {
                int barH = s.PingMs < 0 ? 0 : (int)((s.PingMs / maxPing) * width);
                string bar = new string('█', Math.Max(0, barH)) + new string('░', Math.Max(0, width - barH));
                string val = s.PingMs < 0 ? "   N/A" : $" {s.PingMs,5:F0} ms";
                lines.Add("  " + bar + val);
            }
            lines.Add("  " + new string('─', width + 10));
            return lines.ToArray();
        }

        private static string FitStr(string s, int len)
        {
            if (s == null) return new string(' ', len);
            return s.Length > len ? s.Substring(0, len - 1) + "…" : s.PadRight(len);
        }
    }
}
