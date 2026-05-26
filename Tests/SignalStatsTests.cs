using System;
using System.Linq;
using Xunit;

namespace WifiAnalyzerPro.Tests
{
    public class SignalStatsTests
    {
        // ── Ring buffer ──────────────────────────────────────────

        [Fact]
        public void NewInstance_CountIsZero()
        {
            var s = new SignalStats(10);
            Assert.Equal(0, s.Count);
        }

        [Fact]
        public void AddPoint_CountIncreasesToCapacity()
        {
            var s = new SignalStats(5);
            for (int i = 0; i < 5; i++) s.AddPoint(-60, DateTime.Now);
            Assert.Equal(5, s.Count);
        }

        [Fact]
        public void AddPoint_CountDoesNotExceedCapacity()
        {
            var s = new SignalStats(3);
            for (int i = 0; i < 10; i++) s.AddPoint(-60, DateTime.Now);
            Assert.Equal(3, s.Count);
        }

        [Fact]
        public void GetHistory_ReturnsOldestFirst()
        {
            var s = new SignalStats(5);
            var t0 = new DateTime(2024, 1, 1, 12, 0, 0);
            s.AddPoint(-50, t0);
            s.AddPoint(-60, t0.AddSeconds(1));
            s.AddPoint(-70, t0.AddSeconds(2));

            var h = s.GetHistory();
            Assert.Equal(3, h.Length);
            Assert.Equal(-50, h[0].Rssi);
            Assert.Equal(-70, h[2].Rssi);
        }

        [Fact]
        public void GetHistory_AfterOverflow_OldestIsEvicted()
        {
            var s   = new SignalStats(3);
            var t0  = new DateTime(2024, 1, 1, 12, 0, 0);
            s.AddPoint(-50, t0);               // eviktoituu
            s.AddPoint(-60, t0.AddSeconds(1));
            s.AddPoint(-70, t0.AddSeconds(2));
            s.AddPoint(-80, t0.AddSeconds(3)); // uusin

            var h = s.GetHistory();
            Assert.Equal(3, h.Length);
            Assert.Equal(-60, h[0].Rssi);  // vanhin jäljellä
            Assert.Equal(-80, h[2].Rssi);  // uusin
        }

        [Fact]
        public void Reset_ClearsAllState()
        {
            var s = new SignalStats(10);
            s.AddPoint(-60, DateTime.Now);
            s.AddPoint(-70, DateTime.Now);
            s.Reset();

            Assert.Equal(0, s.Count);
            Assert.Equal(0.0, s.Jitter);
            Assert.Equal(0.0, s.Trend);
            Assert.Empty(s.GetHistory());
        }

        // ── Welford-algoritmi (jitter) ───────────────────────────

        [Fact]
        public void Jitter_FewPoints_ReturnsZero()
        {
            var s = new SignalStats(10);
            s.AddPoint(-60, DateTime.Now);
            s.AddPoint(-65, DateTime.Now);
            // Alle 5 pistettä → 0
            Assert.Equal(0.0, s.Jitter);
        }

        [Fact]
        public void Jitter_ConstantSignal_NearZero()
        {
            var s = new SignalStats(20);
            var t = DateTime.Now;
            for (int i = 0; i < 10; i++) s.AddPoint(-60, t.AddSeconds(i));
            Assert.InRange(s.Jitter, 0.0, 0.1);
        }

        [Fact]
        public void Jitter_AlternatingSignal_HighValue()
        {
            var s = new SignalStats(20);
            var t = DateTime.Now;
            for (int i = 0; i < 10; i++)
                s.AddPoint(i % 2 == 0 ? -50 : -90, t.AddSeconds(i));
            // Vaihtelu 40 dBm → jitter selvästi > 10
            Assert.True(s.Jitter > 10.0,
                $"Odotettu jitter > 10, saatiin {s.Jitter}");
        }

        [Fact]
        public void Jitter_KnownValues_CorrectApproximation()
        {
            // -60, -70, -65 → populaatiovarianssi ≈ sqrt((25+25+0)/3) ≈ 4.08
            var s = new SignalStats(10);
            var t = DateTime.Now;
            s.AddPoint(-60, t);
            s.AddPoint(-70, t.AddSeconds(1));
            s.AddPoint(-65, t.AddSeconds(2));
            s.AddPoint(-60, t.AddSeconds(3));
            s.AddPoint(-70, t.AddSeconds(4));
            Assert.InRange(s.Jitter, 3.5, 5.5);
        }

        // ── EMA-trendi ───────────────────────────────────────────

        [Fact]
        public void Trend_FewPoints_ReturnsZero()
        {
            var s = new SignalStats(10);
            for (int i = 0; i < 5; i++) s.AddPoint(-60, DateTime.Now);
            Assert.Equal(0.0, s.Trend);
        }

        [Fact]
        public void Trend_IncreasingSignal_Positive()
        {
            var s = new SignalStats(30);
            var t = DateTime.Now;
            // Signaali paranee -80 → -50
            for (int i = 0; i < 20; i++)
                s.AddPoint(-80 + i * 2, t.AddSeconds(i));
            Assert.True(s.Trend > 0.0,
                $"Paranevan signaalin trendi pitäisi olla positiivinen, oli {s.Trend}");
        }

        [Fact]
        public void Trend_DecreasingSignal_Negative()
        {
            var s = new SignalStats(30);
            var t = DateTime.Now;
            for (int i = 0; i < 20; i++)
                s.AddPoint(-50 - i * 2, t.AddSeconds(i));
            Assert.True(s.Trend < 0.0,
                $"Heikkenevän signaalin trendi pitäisi olla negatiivinen, oli {s.Trend}");
        }

        // ── SeedFromHistory ──────────────────────────────────────

        [Fact]
        public void SeedFromHistory_LoadsPointsCorrectly()
        {
            var source = new SignalStats(10);
            var t = DateTime.Now;
            source.AddPoint(-60, t);
            source.AddPoint(-65, t.AddSeconds(1));
            source.AddPoint(-70, t.AddSeconds(2));

            var target = new SignalStats(10);
            target.SeedFromHistory(source.GetHistory());

            Assert.Equal(3, target.Count);
            var h = target.GetHistory();
            Assert.Equal(-60, h[0].Rssi);
        }
    }
}
