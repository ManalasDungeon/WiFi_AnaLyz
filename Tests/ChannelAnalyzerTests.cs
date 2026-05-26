using System;
using System.Collections.Generic;
using Xunit;

namespace WifiAnalyzerPro.Tests
{
    public class ChannelAnalyzerTests
    {
        private static ChannelAnalyzer MakeAnalyzer(
            double coW = 6.0, double adjW = 3.0)
            => new ChannelAnalyzer(new WifiConfig
            {
                CoChannelPenaltyWeight = coW,
                AdjacentPenaltyWeight  = adjW
            });

        // ── CalcInterference ─────────────────────────────────────

        [Fact]
        public void CalcInterference_NoNeighbors_ZeroPenalty()
        {
            var ana  = MakeAnalyzer();
            var cnts = new Dictionary<int, int> { [6] = 1 };
            var (co, adj, penalty) = ana.CalcInterference(6, cnts);
            Assert.Equal(0, co);
            Assert.Equal(0, adj);
            Assert.Equal(0.0, penalty);
        }

        [Fact]
        public void CalcInterference_TwoCoChannel_OnePenalty()
        {
            var ana  = MakeAnalyzer();
            var cnts = new Dictionary<int, int> { [6] = 2 };
            var (co, adj, penalty) = ana.CalcInterference(6, cnts);
            Assert.Equal(1, co);
            Assert.Equal(0, adj);
            Assert.Equal(6.0, penalty);
        }

        [Fact]
        public void CalcInterference_AdjacentChannel_Counted()
        {
            var ana  = MakeAnalyzer();
            var cnts = new Dictionary<int, int> { [6] = 1, [7] = 2 };
            var (co, adj, penalty) = ana.CalcInterference(6, cnts);
            Assert.Equal(0, co);
            Assert.Equal(2, adj);
            Assert.Equal(6.0, penalty); // 2 × 3.0
        }

        [Fact]
        public void CalcInterference_5GHz_OnlyImmediateNeighbors()
        {
            var ana  = MakeAnalyzer();
            // 5 GHz: ±1 kanava ei päällekkäin
            var cnts = new Dictionary<int, int> { [36] = 1, [40] = 3 };
            var (co, adj, penalty) = ana.CalcInterference(36, cnts);
            Assert.Equal(0, co);
            Assert.Equal(3, adj);
            Assert.Equal(9.0, penalty); // 3 × 3.0
        }

        [Fact]
        public void CalcInterference_ZeroChannel_NoPenalty()
        {
            var ana   = MakeAnalyzer();
            var cnts  = new Dictionary<int, int> { [0] = 5 };
            var (co, adj, pen) = ana.CalcInterference(0, cnts);
            Assert.Equal(0, co); Assert.Equal(0, adj); Assert.Equal(0.0, pen);
        }

        [Fact]
        public void CalcInterference_5GHz_NoAdjacentBeyondOne()
        {
            var ana  = MakeAnalyzer();
            // Kanava 36 — kanava 44 on ±2 matkan päässä, ei saa laskea 5 GHz:llä
            var cnts = new Dictionary<int, int> { [36] = 1, [44] = 5 };
            var (_, adj, _) = ana.CalcInterference(36, cnts);
            Assert.Equal(0, adj);
        }

        // ── CalcBestChannel2G ────────────────────────────────────

        [Fact]
        public void CalcBestChannel2G_EmptyNetwork_ReturnsChannel1Free()
        {
            var result = ChannelAnalyzer.CalcBestChannel2G(
                new Dictionary<int, int>(), new System.Collections.Generic.HashSet<int>());
            Assert.StartsWith("1", result);
            Assert.Contains("vapaa", result);
        }

        [Fact]
        public void CalcBestChannel2G_Channel1And6Full_Picks11()
        {
            var cnts = new Dictionary<int, int>
            {
                [1] = 5, [2] = 3, [3] = 2, [4] = 1, [5] = 1,
                [6] = 4, [7] = 3, [8] = 2,
            };
            var result = ChannelAnalyzer.CalcBestChannel2G(
                cnts, new System.Collections.Generic.HashSet<int>());
            Assert.StartsWith("11", result);
        }

        [Fact]
        public void CalcBestChannel2G_AllEmpty_Picks1()
        {
            var cnts = new Dictionary<int, int>();
            var result = ChannelAnalyzer.CalcBestChannel2G(
                cnts, new System.Collections.Generic.HashSet<int>());
            Assert.StartsWith("1", result);
        }

        // ── PhyToBand ────────────────────────────────────────────

        [Theory]
        [InlineData(null, 6,   "2.4 GHz")]
        [InlineData(null, 11,  "2.4 GHz")]
        [InlineData(null, 14,  "2.4 GHz")]
        [InlineData(null, 36,  "5 GHz")]
        [InlineData(null, 100, "5 GHz")]
        [InlineData(null, 177, "5 GHz")]
        public void PhyToBand_NullPhy_CorrectBandByChannel(
            string phy, int ch, string expected)
            => Assert.Equal(expected, ChannelAnalyzer.PhyToBand(phy, ch));

        [Theory]
        [InlineData("802.11AC", 36,  "5 GHz")]
        [InlineData("802.11N",  36,  "5 GHz")]
        [InlineData("802.11N",  6,   "2.4 GHz")]
        [InlineData("802.11G",  6,   "2.4 GHz")]
        public void PhyToBand_WithPhy_CorrectBand(string phy, int ch, string expected)
            => Assert.Equal(expected, ChannelAnalyzer.PhyToBand(phy, ch));

        [Fact]
        public void PhyToBand_InvalidChannel_ReturnsQuestionMark()
            => Assert.Equal("?", ChannelAnalyzer.PhyToBand(null, 0));

        // ── RssiToGrade ──────────────────────────────────────────

        [Theory]
        [InlineData(-30, "A")]
        [InlineData(-50, "A")]
        [InlineData(-51, "B")]
        [InlineData(-60, "B")]
        [InlineData(-61, "C")]
        [InlineData(-70, "C")]
        [InlineData(-71, "D")]
        [InlineData(-80, "D")]
        [InlineData(-81, "F")]
        [InlineData(-100,"F")]
        public void RssiToGrade_BoundaryValues(int rssi, string grade)
            => Assert.Equal(grade, ChannelAnalyzer.RssiToGrade(rssi));

        // ── JitterToTag ──────────────────────────────────────────

        [Theory]
        [InlineData(0.0,  "Vakaa")]
        [InlineData(1.9,  "Vakaa")]
        [InlineData(2.0,  "Normaali")]
        [InlineData(4.9,  "Normaali")]
        [InlineData(5.0,  "Epävakaa")]
        [InlineData(8.9,  "Epävakaa")]
        [InlineData(9.0,  "Vaihteleva")]
        [InlineData(15.0, "Vaihteleva")]
        public void JitterToTag_AllBoundaries(double jitter, string tag)
            => Assert.Equal(tag, ChannelAnalyzer.JitterToTag(jitter));

        // ── Tuntikohtainen häiriöseuranta ────────────────────────

        [Fact]
        public void UpdateHourlyInterference_AddsData()
        {
            var ana = MakeAnalyzer();
            var aps = new System.Collections.Generic.List<AnalyzedAccessPoint>
            {
                new AnalyzedAccessPoint { InterferencePenalty = 10.0 },
                new AnalyzedAccessPoint { InterferencePenalty = 20.0 },
            };
            ana.UpdateHourlyInterference(aps);
            var stats = ana.GetHourlyStats();
            Assert.NotEmpty(stats);
            var h = stats.Find(s => s.Hour == DateTime.Now.Hour);
            Assert.NotNull(h);
            Assert.Equal(30.0, h.AvgPenalty, 1);
        }

        [Fact]
        public void GetHourlyStats_Empty_ReturnsEmptyList()
        {
            var ana   = MakeAnalyzer();
            var stats = ana.GetHourlyStats();
            Assert.Empty(stats);
        }
    }
}
