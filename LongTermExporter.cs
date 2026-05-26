using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Kirjoittaa append-only CSV:tä pitkäaikaiseen seurantaan.
    /// KORJAUS: PurgeFile käyttää streaming-kopiointia — ei lataa kaikkia rivejä muistiin.
    /// </summary>
    public class LongTermExporter : IDisposable
    {
        private readonly string _networksPath;
        private readonly string _alertsPath;
        private readonly object _lock = new();
        private bool _networksHeaderWritten;
        private bool _alertsHeaderWritten;
        private DateTime _lastWrittenAlertTime = DateTime.MinValue;

        public LongTermExporter(string directory)
        {
            string dir    = string.IsNullOrWhiteSpace(directory) ? "." : directory;
            _networksPath = Path.Combine(dir, "wifi_longterm_networks.csv");
            _alertsPath   = Path.Combine(dir, "wifi_longterm_alerts.csv");
            _networksHeaderWritten = File.Exists(_networksPath);
            _alertsHeaderWritten   = File.Exists(_alertsPath);
        }

        public void SaveSnapshot(List<AnalyzedAccessPoint> aps, List<AlertEntry> allAlerts = null)
        {
            if (aps == null || aps.Count == 0) return;
            lock (_lock)
            {
                try
                {
                    string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                    using var sw = new StreamWriter(_networksPath, append: true, Encoding.UTF8);
                    if (!_networksHeaderWritten)
                    {
                        sw.WriteLine("ts,bssid,ssid,rssi,grade,channel,band,security,vendor,score,jitter,traffic_kb,co_channel,adjacent,stability,ch_util_pct");
                        _networksHeaderWritten = true;
                    }
                    foreach (var ap in aps)
                        sw.WriteLine(string.Format("{0},{1},{2},{3},{4},{5},{6},{7},{8},{9:F2},{10:F1},{11},{12},{13},{14},{15}",
                            ts, ap.Bssid ?? "", CsvHelper.Escape(ap.Ssid), ap.Rssi, ap.Grade ?? "",
                            ap.Channel, ap.Band ?? "", CsvHelper.Escape(ap.Security),
                            CsvHelper.Escape(ap.Vendor), ap.Score, ap.SignalJitter,
                            ap.TrafficBytes / 1024, ap.CoChannelCount, ap.AdjacentOverlapCount,
                            CsvHelper.Escape(ap.StabilityTag),
                            ap.ChannelUtilization.HasValue ? ap.ChannelUtilization.Value.ToString() : ""));
                }
                catch (Exception ex) { AppLogger.Log($"[LTE] Networks: {ex.Message}"); }

                if (allAlerts != null && allAlerts.Count > 0)
                {
                    var unwritten = allAlerts.Where(a => a.Time > _lastWrittenAlertTime).ToList();
                    if (unwritten.Count > 0)
                    {
                        try
                        {
                            using var sw = new StreamWriter(_alertsPath, append: true, Encoding.UTF8);
                            if (!_alertsHeaderWritten)
                            {
                                sw.WriteLine("ts,type,bssid,message");
                                _alertsHeaderWritten = true;
                            }
                            foreach (var a in unwritten)
                                sw.WriteLine($"{a.Time:yyyy-MM-dd HH:mm:ss},{CsvHelper.Escape(a.Type)},{a.Bssid ?? ""},{CsvHelper.Escape(a.Message)}");
                            _lastWrittenAlertTime = unwritten[unwritten.Count - 1].Time;
                        }
                        catch (Exception ex) { AppLogger.Log($"[LTE] Alerts: {ex.Message}"); }
                    }
                }
            }
        }

        /// <summary>
        /// KORJAUS: Käyttää väliaikaistiedostoa — ei lataa kaikkia rivejä muistiin kerralla.
        /// Aiempi File.ReadAllLines() oli OutOfMemoryException-riskissä suurilla tiedostoilla.
        /// </summary>
        public void PurgeOldRows(TimeSpan maxAge)
        {
            lock (_lock)
            {
                PurgeFileStreaming(_networksPath, maxAge);
                PurgeFileStreaming(_alertsPath,   maxAge);
            }
        }

        private static void PurgeFileStreaming(string path, TimeSpan maxAge)
        {
            if (!File.Exists(path)) return;
            string cutoff = (DateTime.Now - maxAge).ToString("yyyy-MM-dd HH:mm:ss");
            string tmp    = path + ".purge.tmp";
            try
            {
                long kept = 0, removed = 0;
                using (var reader = new StreamReader(path, Encoding.UTF8))
                using (var writer = new StreamWriter(tmp,  append: false, Encoding.UTF8))
                {
                    string header = reader.ReadLine();
                    if (header == null) return;
                    writer.WriteLine(header);

                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.Length >= 19 && string.CompareOrdinal(line, 0, cutoff, 0, 19) >= 0)
                        { writer.WriteLine(line); kept++; }
                        else removed++;
                    }
                }
                if (removed > 0)
                {
                    if (File.Exists(path)) File.Replace(tmp, path, null);
                    else                   File.Move(tmp, path);
                    AppLogger.Log($"[LTE] Purge {Path.GetFileName(path)}: poistettu {removed} riviä, säilytetty {kept}");
                }
                else
                {
                    try { File.Delete(tmp); } catch { }
                }
            }
            catch (Exception ex)
            {
                AppLogger.Log($"[LTE] Purge {path}: {ex.Message}");
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }
        }

        public void Dispose() { }
    }
}
