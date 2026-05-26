using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace WifiAnalyzerPro
{
    // ── Datatyypit ────────────────────────────────────────────────

    /// <summary>Laitteen 24 h baseline-profiili.</summary>
    public class DeviceProfile
    {
        public string   MacAddress   { get; set; }
        public string   Vendor       { get; set; }
        public DateTime FirstSeen    { get; set; } = DateTime.Now;
        public DateTime LastSeen     { get; set; } = DateTime.Now;
        public int      ObservationCount { get; set; }
        /// <summary>Baseline on voimassa kun dataa on vähintään BaselineMinHours tuntia.</summary>
        public bool     IsBaselineReady  { get; set; }
        /// <summary>Viimeisin anomaliapisteet (0–100). 0 = normaali.</summary>
        public int      AnomalyScore     { get; set; }
        public string   AnomalyReason    { get; set; }
    }

    /// <summary>Anomaliahälytys yhdestä laitteesta.</summary>
    public class AnomalyAlert
    {
        public DateTime Time        { get; set; } = DateTime.Now;
        public string   MacAddress  { get; set; }
        public string   Vendor      { get; set; }
        public string   Rule        { get; set; }
        public string   Detail      { get; set; }
        /// <summary>0–100. ≥40 epäilyttävä, ≥70 todennäköinen, ≥90 kriittinen.</summary>
        public int      Score       { get; set; }
    }

    /// <summary>
    /// Behavioral IDS: rakentaa laitekohtaisen normaalikäyttäytymisen profiilin
    /// ja hälyttää kun laite poikkeaa siitä merkittävästi.
    ///
    /// Tunnistettavat anomaliat:
    ///   TRAFFIC_SPIKE  — Liikennepii kki yli 5× tuntikohtainen baseline
    ///   NIGHT_ACTIVITY — Aktiivisuus kellonajalla jolloin laite ei aiemmin herännyt
    ///   ARP_SWEEP      — ARP-kyselytulva (>20/min) = verkkoskannaus
    ///   DNS_EXPLOSION  — Suurin osa DNS-kyselyistä menee tuntemattomiin domaineihin
    ///   DATA_EXFIL     — Korkea liikenne yöllä tuntemattomaan kohteeseen
    ///
    /// Baseline-aika: 4–24 tuntia (luotettavuus kasvaa lineaarisesti).
    /// </summary>
    public sealed class BehaviorProfiler : IDisposable
    {
        // ── Asetukset ─────────────────────────────────────────────
        private const int    BaselineMinHours    = 4;    // vähimmäisaika ennen hälytyksiä
        private const double TrafficSpikeX       = 5.0;  // 5× tuntikohtainen baseline → piikki
        private const int    ArpSweepPerMinute   = 20;   // arp/min kynnys verkkoskannaukseen
        private const double DnsUnknownRatio     = 0.6;  // 60 % tuntemattomia → anomalia
        private const int    DnsWindowMins       = 30;   // DNS-ikkunan pituus
        private const int    MaxProfiles         = 1000; // muistinrajoitus
        private const int    AlertQueueMax       = 200;

        // ── Sisäinen rakenne per laite ────────────────────────────
        private sealed class State
        {
            // 168 tunnin liikennekehyshistoria (7 vrk × 24 h)
            public readonly long[]     HourlyBytes   = new long[168];
            public readonly int[]      HourlyObs     = new int[168];
            // Syklilaskuri per slot: 0 = ei koskaan kirjoitettu.
            // Kun HourSlot() kiertyy ympäri (7 vrk), syklinumero kasvaa →
            // slot nollataan ennen kirjoitusta eikä vanha data akkumuloidu.
            public readonly long[]     HourlySlotEpoch = new long[168];
            // Minimikokoinen lukko slot-nollaukseen — kriittinen osio on vain 3 kenttää
            public readonly object     SlotResetLock = new();
            // Aktiivisuustunnit (0–23) → kuinka monta kertaa havaittu
            public readonly int[]      HourActivity  = new int[24];
            // ARP-aikaikkuna
            public readonly Queue<DateTime> RecentArps = new();
            // DNS-aikaikkuna (viimeiset DnsWindowMins min)
            public readonly Queue<(DateTime T, string Host, bool Known)> RecentDns = new();
            public readonly HashSet<string> KnownHosts = new(StringComparer.OrdinalIgnoreCase);
            // Metadata
            public string   MacAddress;
            public string   Vendor;
            public DateTime FirstSeen   = DateTime.Now;
            public DateTime LastSeen    = DateTime.Now;
            public int      TotalObs;
            // Viimeisin anomalia
            public int      LastScore;
            public string   LastReason;
            public DateTime LastAlertTime = DateTime.MinValue;
        }

        private readonly ConcurrentDictionary<string, State> _states =
            new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentQueue<AnomalyAlert> _alerts = new();
        private readonly Timer _pruneTimer;
        private volatile string _status = "BID: odottaa dataa";

        public string Status => _status;

        public BehaviorProfiler()
        {
            // Siivoa tunnetut tilat kerran tunnissa
            _pruneTimer = new Timer(_ => Prune(), null,
                TimeSpan.FromHours(1), TimeSpan.FromHours(1));
        }

        // ── Datan syöttö ──────────────────────────────────────────

        /// <summary>Kirjaa havaitun liikenteen (bytes) laitteelle.</summary>
        public void RecordTraffic(string mac, string vendor, long bytes)
        {
            if (string.IsNullOrEmpty(mac)) return;
            var s = GetOrCreate(mac, vendor);
            int h = HourSlot();
            long cycle = EpochCycle();

            // KORJAUS: nollaa slot kun se kiertyy 7 vrk:n jälkeen.
            // Ilman nollausta Interlocked.Add akkumuloi vanhan arvon päälle
            // ikuisesti → BaselineForCurrentHour palauttaa virheellistä historiaa
            // ja TRAFFIC_SPIKE-sääntö ei toimi koskaan 7 vrk käynnistyksen jälkeen.
            lock (s.SlotResetLock)
            {
                if (s.HourlySlotEpoch[h] != cycle)
                {
                    s.HourlyBytes[h]    = 0;
                    s.HourlyObs[h]      = 0;
                    s.HourlySlotEpoch[h] = cycle;
                }
            }

            Interlocked.Add(ref s.HourlyBytes[h], bytes);
            Interlocked.Increment(ref s.HourlyObs[h]);
            Interlocked.Increment(ref s.HourActivity[DateTime.Now.Hour]);
            Interlocked.Increment(ref s.TotalObs);
            s.LastSeen = DateTime.Now;
        }

        /// <summary>Kirjaa DNS/TLS SNI -havainto laitteelle.</summary>
        public void RecordDns(string mac, string host)
        {
            if (string.IsNullOrEmpty(mac) || string.IsNullOrEmpty(host)) return;
            var s = GetOrCreate(mac, null);
            lock (s.RecentDns)
            {
                bool known = s.KnownHosts.Contains(host);
                s.RecentDns.Enqueue((DateTime.Now, host, known));
                // Siivoa ikkuna
                var cutoff = DateTime.Now.AddMinutes(-DnsWindowMins);
                while (s.RecentDns.Count > 0 && s.RecentDns.Peek().T < cutoff)
                    s.RecentDns.Dequeue();
                // Lisää tunnettuihin vasta jonkun ajan jälkeen (ei heti ensimmäinen kerta)
                if (known || s.TotalObs > 20) s.KnownHosts.Add(host);
            }
        }

        /// <summary>Kirjaa ARP-probe laitteelle (verkkoskannauksen tunnistukseen).</summary>
        public void RecordArp(string mac)
        {
            if (string.IsNullOrEmpty(mac)) return;
            var s = GetOrCreate(mac, null);
            lock (s.RecentArps)
            {
                s.RecentArps.Enqueue(DateTime.Now);
                var cutoff = DateTime.Now.AddMinutes(-1);
                while (s.RecentArps.Count > 0 && s.RecentArps.Peek() < cutoff)
                    s.RecentArps.Dequeue();
            }
        }

        // ── Anomaliatarkistus ─────────────────────────────────────

        /// <summary>
        /// Tarkistaa kaikkien laitteiden anomaliat.
        /// Kutsutaan periodisesti moottorista (esim. kerran minuutissa).
        /// Palauttaa uudet hälytykset jotka on jo lisätty sisäiseen jonoon.
        /// </summary>
        public List<AnomalyAlert> RunChecks()
        {
            var newAlerts = new List<AnomalyAlert>();
            int profiles  = 0;
            int alerting  = 0;

            foreach (var kv in _states)
            {
                var s = kv.Value;
                if (!IsBaselineReady(s)) continue;

                profiles++;
                var alert = CheckDevice(s);
                if (alert == null) continue;

                // Cooldown: sama laite ei hälytä useammin kuin kerran 10 min
                if ((DateTime.Now - s.LastAlertTime).TotalMinutes < 10) continue;

                s.LastAlertTime = DateTime.Now;
                s.LastScore     = alert.Score;
                s.LastReason    = alert.Rule;

                if (_alerts.Count < AlertQueueMax) _alerts.Enqueue(alert);
                newAlerts.Add(alert);
                alerting++;
            }

            _status = $"BID: {profiles} profiilia, {_states.Count} laitetta";
            return newAlerts;
        }

        private AnomalyAlert CheckDevice(State s)
        {
            var findings = new List<(string Rule, string Detail, int Score)>();

            // ── Sääntö 1: Liikennepiiikki ────────────────────────
            int curH     = HourSlot();
            long curBytes = s.HourlyBytes[curH];
            // Laske baseline: sama tunti viimeisiltä 7 päivältä (jos dataa)
            double baselineMean = BaselineForCurrentHour(s, curH);
            if (baselineMean > 0 && curBytes > baselineMean * TrafficSpikeX)
            {
                double x = curBytes / baselineMean;
                int score = Math.Min(100, (int)(40 + (x - TrafficSpikeX) * 5));
                findings.Add(("TRAFFIC_SPIKE",
                    $"{curBytes/1024} Kt (baseline {baselineMean/1024:F0} Kt × {x:F1})",
                    score));
            }

            // ── Sääntö 2: Yöaktiivisuus (uusi aikaikkuna) ─────────
            int hour = DateTime.Now.Hour;
            if (hour >= 0 && hour <= 5 && s.HourActivity[hour] == 0
                && s.TotalObs > 100) // riittävästi historiaa
            {
                findings.Add(("NIGHT_ACTIVITY",
                    $"Aktiivinen {hour:00}:xx — ei koskaan aiemmin tähän aikaan",
                    55));
            }

            // ── Sääntö 3: ARP-tulva ───────────────────────────────
            int arpPerMin;
            lock (s.RecentArps) arpPerMin = s.RecentArps.Count;
            if (arpPerMin >= ArpSweepPerMinute)
            {
                int score = Math.Min(100, 60 + (arpPerMin - ArpSweepPerMinute) * 2);
                findings.Add(("ARP_SWEEP",
                    $"{arpPerMin} ARP-kyselyä/min (kynnys {ArpSweepPerMinute})",
                    score));
            }

            // ── Sääntö 4: DNS-tulva tuntemattomiin ────────────────
            int totalDns = 0, unknownDns = 0;
            lock (s.RecentDns)
            {
                totalDns   = s.RecentDns.Count;
                unknownDns = s.RecentDns.Count(d => !d.Known);
            }
            if (totalDns >= 10)
            {
                double ratio = (double)unknownDns / totalDns;
                if (ratio >= DnsUnknownRatio)
                {
                    int score = Math.Min(100, (int)(40 + ratio * 50));
                    findings.Add(("DNS_EXPLOSION",
                        $"{unknownDns}/{totalDns} DNS-kyselyä tuntemattomiin " +
                        $"({ratio*100:F0} %, kynnys {DnsUnknownRatio*100:F0} %)",
                        score));
                }
            }

            // ── Sääntö 5: Data-exfiltration yöllä ─────────────────
            if (hour >= 0 && hour <= 5 && curBytes > 10_000_000) // 10 Mt yöllä
            {
                int score = Math.Min(100, 70 + (int)(curBytes / 10_000_000) * 5);
                findings.Add(("DATA_EXFIL",
                    $"{curBytes/1_000_000} Mt siirretty {hour:00}:xx",
                    score));
            }

            if (findings.Count == 0) return null;

            // Käytä korkeinta yksittäistä pisteytystä
            var worst = findings.OrderByDescending(f => f.Score).First();
            return new AnomalyAlert
            {
                MacAddress = s.MacAddress,
                Vendor     = s.Vendor ?? "Tuntematon",
                Rule       = worst.Rule,
                Detail     = worst.Detail + (findings.Count > 1
                    ? $" [+{findings.Count-1} muuta signaalia]" : ""),
                Score      = worst.Score
            };
        }

        private double BaselineForCurrentHour(State s, int currentSlot)
        {
            // Kerää sama tunti muilta päiviltä (24, 48, 72, 96, 120, 144 h sitten)
            var samples  = new List<long>();
            for (int day = 1; day <= 6; day++)
            {
                int slot = (currentSlot - day * 24 + 168) % 168;
                if (s.HourlyObs[slot] > 0) samples.Add(s.HourlyBytes[slot]);
            }
            return samples.Count >= 2 ? samples.Average() : 0;
        }

        private bool IsBaselineReady(State s)
            => (DateTime.Now - s.FirstSeen).TotalHours >= BaselineMinHours;

        // ── Julkinen lukurajapinta ─────────────────────────────────

        public List<AnomalyAlert> DrainAlerts()
        {
            var list = new List<AnomalyAlert>();
            while (_alerts.TryDequeue(out var a)) list.Add(a);
            return list;
        }

        public List<DeviceProfile> GetProfiles()
        {
            return _states.Values.Select(s => new DeviceProfile
            {
                MacAddress      = s.MacAddress,
                Vendor          = s.Vendor,
                FirstSeen       = s.FirstSeen,
                LastSeen        = s.LastSeen,
                ObservationCount = s.TotalObs,
                IsBaselineReady = IsBaselineReady(s),
                AnomalyScore    = s.LastScore,
                AnomalyReason   = s.LastReason
            }).OrderByDescending(p => p.AnomalyScore).ToList();
        }

        // ── Apufunktiot ───────────────────────────────────────────

        private State GetOrCreate(string mac, string vendor)
        {
            if (_states.TryGetValue(mac, out var existing))
            {
                if (vendor != null && existing.Vendor == null) existing.Vendor = vendor;
                return existing;
            }
            if (_states.Count >= MaxProfiles) return new State { MacAddress = mac };
            var s = new State { MacAddress = mac, Vendor = vendor };
            _states[mac] = s;
            return s;
        }

        /// <summary>168-tunnin slot (0–167) nykyiselle hetkelle.</summary>
        private static int HourSlot()
        {
            var epoch = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Local);
            return (int)((DateTime.Now - epoch).TotalHours % 168);
        }

        /// <summary>
        /// 7 vrk -syklinumero (0, 1, 2, …). Kun HourSlot kiertyy ympäri,
        /// EpochCycle kasvaa — tämä erottaa saman slot-indeksin eri sykleillä.
        /// </summary>
        private static long EpochCycle()
        {
            var epoch = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Local);
            return (long)((DateTime.Now - epoch).TotalHours) / 168;
        }

        private void Prune()
        {
            var cutoff = DateTime.Now.AddDays(-8);
            foreach (var kv in _states.ToArray())
                if (kv.Value.LastSeen < cutoff && _states.TryRemove(kv.Key, out _)) { }
        }

        public void Dispose() => _pruneTimer?.Dispose();
    }
}
