using System;
using System.Collections.Generic;
using System.Threading;
using Xunit;

namespace WifiAnalyzerPro.Tests
{
    public class AlertManagerTests
    {
        private static AlertManager Make(int cooldown = 60, bool alertOnNewAp = true)
            => new AlertManager(new WifiConfig
            {
                AlertCooldownSeconds = cooldown,
                AlertOnNewAp         = alertOnNewAp,
                AlertLogPath         = System.IO.Path.GetTempFileName(),
                AlertWebhookUrl      = "",  // ei HTTP-kutsuja testeissä
                SuppressedAlertTypes = new List<string>()
            });

        // ── Add + GetAll ─────────────────────────────────────────

        [Fact]
        public void Add_NewAlert_AppearsInGetAll()
        {
            var mgr = Make();
            mgr.Add("TestType", "AA:BB:CC:DD:EE:FF", "testiviesti");
            var all = mgr.GetAll();
            Assert.Single(all);
            Assert.Equal("TestType", all[0].Type);
            Assert.Equal("AA:BB:CC:DD:EE:FF", all[0].Bssid);
        }

        [Fact]
        public void Add_MaxAlerts_OldestEvicted()
        {
            var mgr = Make(cooldown: 0);
            // Lisää 501 hälytystä — max on 500
            for (int i = 0; i < 501; i++)
                mgr.Add($"Type{i}", $"AA:BB:CC:DD:{i:X2}:00", $"msg {i}");
            Assert.Equal(500, mgr.GetAll().Count);
        }

        [Fact]
        public void GetAll_ReturnsSnapshot_NotLiveList()
        {
            var mgr  = Make();
            mgr.Add("A", "AA:BB", "1");
            var snap1 = mgr.GetAll();
            mgr.Add("B", "CC:DD", "2");
            // snap1 pitäisi olla kopio — ei muutu
            Assert.Single(snap1);
        }

        // ── Cooldown ─────────────────────────────────────────────

        [Fact]
        public void Add_SameTypeBssid_BlockedByCooldown()
        {
            var mgr = Make(cooldown: 60);
            mgr.Add("WeakSignal", "AA:BB", "1. hälytys");
            mgr.Add("WeakSignal", "AA:BB", "2. hälytys (pitäisi blokkaantua)");
            Assert.Single(mgr.GetAll());
        }

        [Fact]
        public void Add_DifferentBssid_BothAllowed()
        {
            var mgr = Make(cooldown: 60);
            mgr.Add("WeakSignal", "AA:BB", "AP 1");
            mgr.Add("WeakSignal", "CC:DD", "AP 2");
            Assert.Equal(2, mgr.GetAll().Count);
        }

        [Fact]
        public void Add_DifferentType_BothAllowed()
        {
            var mgr = Make(cooldown: 60);
            mgr.Add("WeakSignal",  "AA:BB", "heikko signaali");
            mgr.Add("EvilTwin",    "AA:BB", "evil twin");
            Assert.Equal(2, mgr.GetAll().Count);
        }

        [Fact]
        public void Add_ZeroCooldown_AllowsDuplicates()
        {
            var mgr = Make(cooldown: 0);
            mgr.Add("Type", "AA:BB", "1");
            mgr.Add("Type", "AA:BB", "2");
            mgr.Add("Type", "AA:BB", "3");
            Assert.Equal(3, mgr.GetAll().Count);
        }

        [Fact]
        public void Add_AfterCooldown_AllowsAgain()
        {
            // Cooldown 1 s — odota 1.1 s
            var mgr = Make(cooldown: 1);
            mgr.Add("Type", "AA:BB", "1. hälytys");
            Thread.Sleep(1100);
            mgr.Add("Type", "AA:BB", "2. hälytys (cooldown kulunut)");
            Assert.Equal(2, mgr.GetAll().Count);
        }

        // ── SuppressedAlertTypes ─────────────────────────────────

        [Fact]
        public void Add_SuppressedType_NotAdded()
        {
            var mgr = new AlertManager(new WifiConfig
            {
                AlertCooldownSeconds = 0,
                AlertLogPath         = System.IO.Path.GetTempFileName(),
                AlertWebhookUrl      = "",
                SuppressedAlertTypes = new List<string> { "NewAP" }
            });
            mgr.Add("NewAP", "AA:BB", "pitäisi ohittua");
            Assert.Empty(mgr.GetAll());
        }

        [Fact]
        public void Add_NonSuppressedType_IsAdded()
        {
            var mgr = new AlertManager(new WifiConfig
            {
                AlertCooldownSeconds = 0,
                AlertLogPath         = System.IO.Path.GetTempFileName(),
                AlertWebhookUrl      = "",
                SuppressedAlertTypes = new List<string> { "NewAP" }
            });
            mgr.Add("EvilTwin", "AA:BB", "tämä menee läpi");
            Assert.Single(mgr.GetAll());
        }

        // ── Hystereesi (WeakSignal) ───────────────────────────────

        [Fact]
        public void IsWeakSignal_NewBssid_ReturnsFalse()
        {
            var mgr = Make();
            Assert.False(mgr.IsWeakSignal("AA:BB:CC:DD:EE:FF"));
        }

        [Fact]
        public void SetWeakSignal_True_IsWeakSignalReturnsTrue()
        {
            var mgr = Make();
            mgr.SetWeakSignal("AA:BB", true);
            Assert.True(mgr.IsWeakSignal("AA:BB"));
        }

        [Fact]
        public void SetWeakSignal_TrueThenFalse_ReturnsFalse()
        {
            var mgr = Make();
            mgr.SetWeakSignal("AA:BB", true);
            mgr.SetWeakSignal("AA:BB", false);
            Assert.False(mgr.IsWeakSignal("AA:BB"));
        }

        [Fact]
        public void SetWeakSignal_DifferentBssids_Independent()
        {
            var mgr = Make();
            mgr.SetWeakSignal("AA:BB", true);
            mgr.SetWeakSignal("CC:DD", false);
            Assert.True(mgr.IsWeakSignal("AA:BB"));
            Assert.False(mgr.IsWeakSignal("CC:DD"));
        }

        // ── IsSecurityDowngrade ───────────────────────────────────

        [Theory]
        [InlineData("WPA3", "WPA2",    true)]   // WPA3 → WPA2 = lasku
        [InlineData("WPA3", "WPA",     true)]   // WPA3 → WPA = lasku
        [InlineData("WPA3", "Open",    true)]   // WPA3 → Open = lasku
        [InlineData("WPA2", "WPA",     true)]   // WPA2 → WPA = lasku
        [InlineData("WPA2", "Open",    true)]   // WPA2 → Open = lasku
        [InlineData("WPA",  "Open",    true)]   // WPA → Open = lasku
        [InlineData("WPA2", "WPA3",    false)]  // WPA2 → WPA3 = päivitys, ei lasku
        [InlineData("WPA3", "WPA3",    false)]  // sama taso
        [InlineData("WPA2", "WPA2",    false)]  // sama taso
        [InlineData("Open", "WPA2",    false)]  // avoin → WPA2 = päivitys
        [InlineData("WPA2-Ent", "WPA2",true)]   // Ent → PSK = lasku (Ent on taso 3)
        [InlineData("",    "WPA2",     false)]  // tyhjä vanhasuoja = ei laskua
        [InlineData("WPA2","",         false)]  // tyhjä uusisuoja = ei laskua
        public void IsSecurityDowngrade_AllCases(string old, string newSec, bool expected)
            => Assert.Equal(expected, AlertManager.IsSecurityDowngrade(old, newSec));

        // ── IsMacRandomized ───────────────────────────────────────

        [Theory]
        // LA-bitti (bit 1 ensimmäisessä oktetissa) asetettu
        [InlineData("02:11:22:33:44:55", true)]   // 0x02 = LA asetettu
        [InlineData("06:AB:CD:EF:00:11", true)]   // 0x06 = LA+multicast
        [InlineData("EA:BB:CC:DD:EE:FF", true)]   // 0xEA = ...10 → LA asetettu
        // LA-bitti ei asetettu (OUI-rekisteröity, globaalisti yksilöllinen)
        [InlineData("00:50:F2:11:22:33", false)]  // Intel/Microsoft OUI
        [InlineData("AC:DE:48:AA:BB:CC", false)]  // normaali OUI
        [InlineData("FC:EC:DA:11:22:33", false)]  // Apple OUI
        // Reunatapaukset
        [InlineData("", false)]
        [InlineData(null, false)]
        [InlineData("ZZ:ZZ", false)]              // virheellinen MAC
        public void IsMacRandomized_AllCases(string mac, bool expected)
            => Assert.Equal(expected, AlertManager.IsMacRandomized(mac));

        // ── Snapshot ─────────────────────────────────────────────

        [Fact]
        public void Snapshot_ReturnsReadOnlyView()
        {
            var mgr  = Make(cooldown: 0);
            mgr.Add("A", "AA", "1");
            mgr.Add("B", "BB", "2");
            var snap = mgr.Snapshot();
            Assert.Equal(2, snap.Count);
            Assert.IsAssignableFrom<System.Collections.Generic.IReadOnlyList<AlertEntry>>(snap);
        }
    }
}
