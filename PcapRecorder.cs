using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Forensinen PCAP-nauhoitus. Kirjoittaa standardin libpcap-muodon
    /// (.pcap) BinaryWriter:llä ilman SharpPcap-sisäisten tyyppien käyttöä.
    /// Wireshark avaa tiedoston suoraan — linkkityyppi 127 (802.11 + radiotap).
    ///
    /// Käynnistyy automaattisesti:
    ///   • Evil Twin -hälytys (confidence >= 2)
    ///   • Blacklist-taso 3 (C2, cryptominer jne.)
    ///   • Varmennettu PMF-deauth-hyökkäys
    ///   • Honeypot-laukaisu
    /// </summary>
    public sealed class PcapRecorder : IDisposable
    {
        // libpcap global header -vakiot
        private const uint   PcapMagic   = 0xA1B2C3D4; // little-endian, microsekunnit
        private const ushort MajorVer    = 2;
        private const ushort MinorVer    = 4;
        private const int    Snaplen     = 65535;
        private const uint   LinkType    = 127;          // IEEE 802.11 + radiotap

        private readonly string _dir;
        private readonly int    _durationSec;
        private readonly long   _maxBytes;
        private readonly int    _maxConcurrent;
        private int             _activeCount;

        public PcapRecorder(WifiConfig cfg)
        {
            _dir           = cfg.CaptureDirectory ?? ".";
            _durationSec   = Math.Max(5, cfg.CaptureDurationSeconds);
            _maxBytes      = cfg.CaptureMaxFileSizeBytes > 0
                             ? cfg.CaptureMaxFileSizeBytes : 52_428_800;
            _maxConcurrent = Math.Max(1, cfg.MaxConcurrentCaptures);
            try { Directory.CreateDirectory(_dir); } catch { }
        }

        /// <summary>
        /// Käynnistää PCAP-nauhoituksen taustasäikeessä.
        /// Palauttaa tiedostopolun tai null jos nauhoitus ei käynnistynyt.
        /// </summary>
        public string Start(
            string triggerMac,
            string reason,
            Action<Action<byte[], DateTime>> attachProcessor,
            Action<Action<byte[], DateTime>> detachProcessor)
        {
            if (Interlocked.CompareExchange(ref _activeCount, 0, 0) >= _maxConcurrent)
            {
                AppLogger.Log($"[PCAP] Ohitettu: {_activeCount}/{_maxConcurrent} käynnissä");
                return null;
            }

            string macSafe    = (triggerMac ?? "unknown")
                .Replace(":", "").Replace("-", "").ToUpperInvariant();
            string reasonSafe = SanitizeFileName(reason ?? "trigger");
            string ts         = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string path       = Path.Combine(_dir,
                $"capture_{ts}_{reasonSafe}_{macSafe}.pcap");

            AppLogger.Log($"[PCAP] Aloitetaan: {path}  " +
                          $"({_durationSec} s, max {_maxBytes / 1_048_576} Mt)");

            Task.Run(() => RecordLoop(path, triggerMac, attachProcessor, detachProcessor));
            return path;
        }

        private void RecordLoop(
            string path,
            string filterMac,
            Action<Action<byte[], DateTime>> attach,
            Action<Action<byte[], DateTime>> detach)
        {
            Interlocked.Increment(ref _activeCount);
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_durationSec));

            try
            {
                using var fs     = new FileStream(path, FileMode.Create,
                                       FileAccess.Write, FileShare.Read);
                using var writer = new BinaryWriter(fs);

                WritePcapHeader(writer);
                long bytesWritten = 0;

                Action<byte[], DateTime> handler = (pkt, pktTs) =>
                {
                    if (cts.IsCancellationRequested) return;
                    if (!MatchesMac(pkt, filterMac))  return;

                    try
                    {
                        lock (writer)
                        {
                            WritePcapPacket(writer, pkt, pktTs);
                            bytesWritten += 16 + pkt.Length;
                        }

                        if (bytesWritten >= _maxBytes)
                        {
                            AppLogger.Log("[PCAP] Kokoraja saavutettu");
                            cts.Cancel();
                        }
                    }
                    catch { }
                };

                attach(handler);
                cts.Token.WaitHandle.WaitOne();
                detach(handler);

                AppLogger.Log($"[PCAP] Valmis: {path}  ({bytesWritten / 1024} Kt)");
            }
            catch (Exception ex)
            {
                AppLogger.Log($"[PCAP] Virhe: {ex.Message}");
                try
                {
                    if (File.Exists(path) && new FileInfo(path).Length < 24)
                        File.Delete(path);
                }
                catch { }
            }
            finally
            {
                Interlocked.Decrement(ref _activeCount);
                cts.Dispose();
            }
        }

        // ── libpcap-muoto ─────────────────────────────────────────

        private static void WritePcapHeader(BinaryWriter w)
        {
            w.Write(PcapMagic);     // magic number
            w.Write(MajorVer);      // version_major
            w.Write(MinorVer);      // version_minor
            w.Write(0);             // thiszone (UTC)
            w.Write(0u);            // sigfigs
            w.Write((uint)Snaplen); // snaplen
            w.Write(LinkType);      // network (127 = 802.11 + radiotap)
            w.Flush();
        }

        private static void WritePcapPacket(BinaryWriter w, byte[] pkt, DateTime ts)
        {
            // Muunna UTC-aikaero Unix-epookista mikrosekunneiksi
            var  epoch   = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            long usTicks = (ts.ToUniversalTime() - epoch).Ticks / 10; // 100 ns → µs
            uint tsSec   = (uint)(usTicks / 1_000_000);
            uint tsUsec  = (uint)(usTicks % 1_000_000);
            uint capLen  = (uint)Math.Min(pkt.Length, Snaplen);

            w.Write(tsSec);
            w.Write(tsUsec);
            w.Write(capLen);
            w.Write((uint)pkt.Length);
            w.Write(pkt, 0, (int)capLen);
            w.Flush();
        }

        // ── MAC-suodatin ──────────────────────────────────────────

        private static bool MatchesMac(byte[] pkt, string filterMac)
        {
            if (string.IsNullOrEmpty(filterMac) || filterMac == "unknown")
                return true;

            var target = new byte[6];
            try
            {
                string raw = filterMac.Replace(":", "").Replace("-", "");
                if (raw.Length < 12) return false;
                for (int i = 0; i < 6; i++)
                    target[i] = Convert.ToByte(raw.Substring(i * 2, 2), 16);
            }
            catch { return false; }

            if (pkt.Length < 4) return false;
            int rtLen = pkt[2] | (pkt[3] << 8);
            if (rtLen + 24 > pkt.Length) return false;

            // Tarkista Address1 (DA), Address2 (SA), Address3 (BSSID)
            foreach (int addrOff in new[] { rtLen + 4, rtLen + 10, rtLen + 16 })
            {
                if (addrOff + 6 > pkt.Length) break;
                bool match = true;
                for (int i = 0; i < 6; i++)
                    if (pkt[addrOff + i] != target[i]) { match = false; break; }
                if (match) return true;
            }
            return false;
        }

        private static string SanitizeFileName(string s)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
                s = s.Replace(c, '_');
            return s.Length > 20 ? s.Substring(0, 20) : s;
        }

        public int  ActiveCount => Interlocked.CompareExchange(ref _activeCount, 0, 0);
        public void Dispose()   { }
    }
}
