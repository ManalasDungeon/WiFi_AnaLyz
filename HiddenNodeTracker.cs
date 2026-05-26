using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Seuraa 802.11 Control-kehysten RTS (Request to Send, subtype 11)
    /// ja CTS (Clear to Send, subtype 12) esiintymisiä kanavittain.
    ///
    /// "Piilotettu solmu" -ongelma (hidden terminal problem):
    ///   Asiakas A voi kuulla AP:n muttei asiakasta B. Jos molemmat lähettävät
    ///   samanaikaisesti, törmäys tapahtuu AP:ssa. RTS/CTS-kättely ratkaisee
    ///   tämän: korkea RTS-määrä ilman CTS-vastausta vihjaa piilotettuun solmuun.
    ///
    /// Liikenteen analyysi avoimissa verkoissa (DNS + TLS SNI):
    ///   Jos verkko on avoin (salaamaton), Data-kehykset voidaan purkaa
    ///   Layer 3+ -sisällöstä ja poimia DNS-kyselyitä ja TLS SNI -nimiä.
    ///   HUOMIO: Tämä on laillista vain omistamissasi verkoissa tai
    ///   nimenomaisen luvan kanssa. Oletuksena pois käytöstä.
    /// </summary>
    public class HiddenNodeTracker
    {
        private const int WindowSeconds   = 30;
        private const double SuspectThreshold = 0.70;
        private const int MinRtsForAlert  = 20;

        private readonly ConcurrentDictionary<int, (Queue<DateTime> Rts, Queue<DateTime> Cts)> _byChannel = new();
        private readonly object _lock = new();

        // DPI: havainnot (Name → tilannevedos) — sisältää nyt palvelutiedot
        private readonly ConcurrentDictionary<string, TrafficObservation> _observations =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly DpiAnalyzer _dpi;

        /// <summary>
        /// Tapahtuma joka laukaistaan kun uusi tai päivitetty DPI-havainto on valmis.
        /// Parametri on valmis TrafficObservation-olio kaikilla kentillä täytettynä.
        /// Program.cs ohjaa tämän WebDashboard.PushDpiEvent():lle.
        /// </summary>
        public event Action<TrafficObservation> ObservationRecorded;

        public HiddenNodeTracker(DpiAnalyzer dpi = null)
        {
            _dpi = dpi;
        }

        public void RecordRts(int channel)
        {
            lock (_lock)
            {
                var pair = GetOrCreate(channel);
                pair.Rts.Enqueue(DateTime.Now);
            }
        }

        public void RecordCts(int channel)
        {
            lock (_lock)
            {
                var pair = GetOrCreate(channel);
                pair.Cts.Enqueue(DateTime.Now);
            }
        }

        private (Queue<DateTime> Rts, Queue<DateTime> Cts) GetOrCreate(int channel)
        {
            if (!_byChannel.TryGetValue(channel, out var pair))
            {
                pair = (new Queue<DateTime>(256), new Queue<DateTime>(256));
                _byChannel[channel] = pair;
            }
            return pair;
        }

        /// <summary>
        /// Laskee RTS/CTS-statistiikan kaikilta seuratuilta kanavilta.
        /// Puhdistaa vanhat merkinnät liukuvasta ikkunasta.
        /// </summary>
        public List<HiddenNodeStat> GetStats()
        {
            var cutoff = DateTime.Now.AddSeconds(-WindowSeconds);
            var result = new List<HiddenNodeStat>();

            lock (_lock)
            {
                foreach (var kv in _byChannel)
                {
                    var (rts, cts) = kv.Value;
                    // Purge
                    while (rts.Count > 0 && rts.Peek() < cutoff) rts.Dequeue();
                    while (cts.Count > 0 && cts.Peek() < cutoff) cts.Dequeue();

                    int rtsN = rts.Count;
                    int ctsN = cts.Count;
                    if (rtsN == 0) continue;

                    result.Add(new HiddenNodeStat
                    {
                        Channel    = kv.Key,
                        RtsCount   = rtsN,
                        CtsCount   = ctsN,
                        MissedCts  = Math.Max(0, rtsN - ctsN)
                    });
                }
            }
            return result.OrderByDescending(s => s.MissedCts).ToList();
        }

        // ── DNS-kaappaus avoimissa verkoissa ────────────────────────

        /// <summary>
        /// Yrittää parsia DNS A/AAAA-kyselyn avoimesta (salaamattomasta) kehyksestä.
        /// Palauttaa null jos kehys ei ole DNS-kysely tai parsinta epäonnistuu.
        ///
        /// Kutsutaan PassiveChannelScannerilta kun Data-kehys on avoimesta verkosta.
        /// </summary>
        public static string TryParseDnsQuery(byte[] payload, int off)
        {
            try
            {
                // Etsi UDP-paketti (protocol 17) IP-kerroksesta
                if (off + 20 > payload.Length) return null;
                if (payload[off + 9] != 17) return null; // ei UDP

                int ihl    = (payload[off] & 0x0F) * 4;
                int udpOff = off + ihl;
                if (udpOff + 8 > payload.Length) return null;

                ushort dstPort = (ushort)((payload[udpOff + 2] << 8) | payload[udpOff + 3]);
                if (dstPort != 53) return null; // ei DNS

                int dnsOff = udpOff + 8;
                if (dnsOff + 12 > payload.Length) return null;

                // DNS-otsikko: flags (2B) — QR bit (bit 15) = 0 on kysely
                ushort flags = (ushort)((payload[dnsOff + 2] << 8) | payload[dnsOff + 3]);
                if ((flags & 0x8000) != 0) return null; // vastaus, ei kysely

                // QCOUNT pitää olla >= 1
                ushort qdCount = (ushort)((payload[dnsOff + 4] << 8) | payload[dnsOff + 5]);
                if (qdCount < 1) return null;

                // Lue ensimmäinen DNS-nimi
                int pos = dnsOff + 12;
                var sb = new System.Text.StringBuilder();
                while (pos < payload.Length)
                {
                    int len = payload[pos++];
                    if (len == 0) break;
                    // Kompressio-osoitin (0xC0) — ei tueta, palataan
                    if ((len & 0xC0) == 0xC0) break;
                    if (sb.Length > 0) sb.Append('.');
                    if (pos + len > payload.Length) break;
                    sb.Append(System.Text.Encoding.ASCII.GetString(payload, pos, len));
                    pos += len;
                }
                string hostname = sb.ToString();
                return hostname.Length > 3 ? hostname : null;
            }
            catch { return null; }
        }

        /// <summary>
        /// Yrittää parsia TLS Client Hello -kehyksen SNI-tiedon (Server Name Indication).
        /// Mahdollistaa kohdepalvelimen tunnistuksen salatusta HTTPS-yhteydestä.
        /// Toimii vain avoimissa verkoissa joissa 802.11-kehykset eivät ole salattuja.
        /// </summary>
        public static string TryParseTlsSni(byte[] payload, int off)
        {
            try
            {
                if (off + 20 > payload.Length) return null;
                if (payload[off + 9] != 6) return null; // ei TCP

                int ihl    = (payload[off] & 0x0F) * 4;
                int tcpOff = off + ihl;
                if (tcpOff + 20 > payload.Length) return null;

                ushort dstPort = (ushort)((payload[tcpOff + 2] << 8) | payload[tcpOff + 3]);
                if (dstPort != 443) return null; // ei HTTPS

                int dataOff = tcpOff + ((payload[tcpOff + 12] >> 4) * 4);
                if (dataOff + 5 > payload.Length) return null;

                // TLS record: ContentType=22 (Handshake) + Version + Length
                if (payload[dataOff] != 22) return null; // ei Handshake

                int hsOff = dataOff + 5;
                if (hsOff + 4 > payload.Length) return null;
                if (payload[hsOff] != 1) return null; // ei Client Hello

                // Hyppää yli: type(1) + length(3) + version(2) + random(32) + session_id_len(1)
                int pos = hsOff + 4 + 2 + 32;
                if (pos + 1 > payload.Length) return null;
                int sidLen = payload[pos++];
                pos += sidLen;
                if (pos + 2 > payload.Length) return null;

                int csLen = (payload[pos] << 8) | payload[pos + 1]; pos += 2;
                pos += csLen;
                if (pos + 1 > payload.Length) return null;
                int cmLen = payload[pos++]; pos += cmLen;

                // Extensions
                if (pos + 2 > payload.Length) return null;
                int extTotal = (payload[pos] << 8) | payload[pos + 1]; pos += 2;
                int extEnd   = pos + extTotal;

                while (pos + 4 <= extEnd && pos + 4 <= payload.Length)
                {
                    int extType = (payload[pos] << 8) | payload[pos + 1]; pos += 2;
                    int extLen  = (payload[pos] << 8) | payload[pos + 1]; pos += 2;

                    if (extType == 0 && extLen > 5) // server_name extension
                    {
                        // list_len(2) + type(1) + name_len(2) + name
                        int nameLen = (payload[pos + 3] << 8) | payload[pos + 4];
                        if (pos + 5 + nameLen <= payload.Length)
                        {
                            string sni = System.Text.Encoding.ASCII.GetString(payload, pos + 5, nameLen);
                            return sni.Length > 3 ? sni : null;
                        }
                    }
                    pos += extLen;
                }
            }
            catch { }
            return null;
        }

        public void RecordDnsHostname(string hostname, string srcMac = null, string bssid = null)
        {
            if (string.IsNullOrWhiteSpace(hostname)) return;
            RecordObservation(hostname, "DNS", srcMac, bssid);
        }

        public void RecordTlsSni(string sni, string srcMac = null, string bssid = null)
        {
            if (string.IsNullOrWhiteSpace(sni)) return;
            RecordObservation(sni, "TLS-SNI", srcMac, bssid);
        }

        private void RecordObservation(string name, string kind, string srcMac, string bssid)
        {
            string svc = null;
            bool   blacklisted = false;
            int    sev  = 0;
            string why  = null;

            if (_dpi != null)
            {
                var (serviceName, hit) = _dpi.Analyze(name);
                svc = serviceName;
                if (hit != null)
                {
                    blacklisted = true;
                    sev  = hit.Severity;
                    why  = hit.Reason;
                }
            }

            var obs = new TrafficObservation
            {
                Name              = name,
                LastSeen          = DateTime.Now,
                Kind              = kind,
                SourceMac         = srcMac,
                Bssid             = bssid,
                ServiceName       = svc,
                IsBlacklisted     = blacklisted,
                BlacklistSeverity = sev,
                BlacklistReason   = why
            };

            _observations[name] = obs;
            ObservationRecorded?.Invoke(obs);
        }

        /// <summary>Palauttaa DPI-havainnot viimeiseltä maxAgeMinutes minuutilta.</summary>
        public List<TrafficObservation> GetObservations(int maxAgeMinutes = 10)
        {
            var cutoff = DateTime.Now.AddMinutes(-maxAgeMinutes);
            return _observations.Values
                .Where(o => o.LastSeen > cutoff)
                .OrderByDescending(o => o.IsBlacklisted)
                .ThenByDescending(o => o.LastSeen)
                .Take(100).ToList();
        }

        /// <summary>Palauttaa DNS-kyselyhavaitut hostnamet viimeiseltä maxAgeMinutes minuutilta.</summary>
        public List<(string Host, DateTime LastSeen)> GetDnsHostnames(int maxAgeMinutes = 5)
        {
            var cutoff = DateTime.Now.AddMinutes(-maxAgeMinutes);
            return _observations.Values
                .Where(o => o.Kind == "DNS" && o.LastSeen > cutoff)
                .Select(o => (o.Name, o.LastSeen))
                .OrderByDescending(t => t.LastSeen).Take(50).ToList();
        }

        /// <summary>Palauttaa TLS SNI -havaitut palvelimet viimeiseltä maxAgeMinutes minuutilta.</summary>
        public List<(string Sni, DateTime LastSeen)> GetTlsSnis(int maxAgeMinutes = 5)
        {
            var cutoff = DateTime.Now.AddMinutes(-maxAgeMinutes);
            return _observations.Values
                .Where(o => o.Kind == "TLS-SNI" && o.LastSeen > cutoff)
                .Select(o => (o.Name, o.LastSeen))
                .OrderByDescending(t => t.LastSeen).Take(50).ToList();
        }

        public void Clear()
        {
            lock (_lock) { _byChannel.Clear(); }
            _observations.Clear();
        }
    }
}
