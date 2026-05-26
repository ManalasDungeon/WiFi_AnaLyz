using System;
using System.IO;
using Xunit;

namespace WifiAnalyzerPro.Tests
{
    public class OuiDatabaseTests
    {
        // ── Normalize ────────────────────────────────────────────

        [Theory]
        [InlineData("AA:BB:CC:DD:EE:FF", "AABBCC")]
        [InlineData("aa:bb:cc:dd:ee:ff", "AABBCC")]
        [InlineData("AA-BB-CC-DD-EE-FF", "AABBCC")]
        [InlineData("AABBCCDDEEFF",       "AABBCC")]
        [InlineData("AA BB CC DD EE FF",  "AABBCC")]
        [InlineData("\"AABBCC\"",         "AABBCC")]  // lainausmerkit trimmataan
        [InlineData("",                   "")]
        [InlineData(null,                 "")]
        public void Normalize_VariousFormats(string input, string expected)
            => Assert.Equal(expected, OuiDatabase.Normalize(input));

        // ── Lataus: yksinkertainen 2-sarake formaatti ─────────────

        [Fact]
        public void Load_SimpleTwoColumnFormat_VendorFound()
        {
            string path = WriteTempCsv(
                "0050F2,Microsoft Corporation\n" +
                "FCECDA,Apple Inc.\n");

            var db = new OuiDatabase();
            db.LoadFromPath(path);

            Assert.Equal("Microsoft Corporation", db.Lookup("00:50:F2:11:22:33"));
            Assert.Equal("Apple Inc.",            db.Lookup("FC:EC:DA:AA:BB:CC"));
        }

        [Fact]
        public void Load_SimpleTwoColumnWithColon_VendorFound()
        {
            string path = WriteTempCsv("00:50:F2,Microsoft Corp\n");
            var db = new OuiDatabase();
            db.LoadFromPath(path);
            Assert.Equal("Microsoft Corp", db.Lookup("00:50:F2:00:00:00"));
        }

        // ── Lataus: IEEE virallinen 4-sarake formaatti ────────────

        [Fact]
        public void Load_IeeeFourColumnFormat_VendorFound()
        {
            // IEEE oui.csv: Registry,Assignment,Organization Name,Org Address
            string path = WriteTempCsv(
                "Registry,Assignment,Organization Name,Organization Address\n" +
                "MA-L,0C0EF2,AVM GmbH,\"AVM Audiovisuelles Marketing\"\n" +
                "MA-L,FCECDA,Apple Inc.,\"One Apple Park Way\"\n");

            var db = new OuiDatabase();
            db.LoadFromPath(path);

            Assert.Equal("AVM GmbH",   db.Lookup("0C:0E:F2:11:22:33"));
            Assert.Equal("Apple Inc.", db.Lookup("FC:EC:DA:AA:BB:CC"));
        }

        [Fact]
        public void Load_IeeeFourColumn_SkipsHeaderCorrectly()
        {
            string path = WriteTempCsv(
                "Registry,Assignment,Organization Name,Organization Address\n" +
                "MA-L,001122,TestVendor,TestAddress\n");
            var db = new OuiDatabase();
            db.LoadFromPath(path);
            // Otsikkorivi ei saa olla vendor
            Assert.NotEqual("Assignment", db.Lookup("00:11:22:33:44:55"));
            Assert.Equal("TestVendor",    db.Lookup("00:11:22:33:44:55"));
        }

        // ── Lataus: reunatapaukset ────────────────────────────────

        [Fact]
        public void Load_EmptyFile_NoException()
        {
            string path = WriteTempCsv("");
            var db = new OuiDatabase();
            db.LoadFromPath(path);
            Assert.Equal("Unknown", db.Lookup("AA:BB:CC:DD:EE:FF"));
        }

        [Fact]
        public void Load_QuotedVendorName_NoBogusQuotes()
        {
            string path = WriteTempCsv("AABBCC,\"Intel Corporation\"\n");
            var db = new OuiDatabase();
            db.LoadFromPath(path);
            // Varmista ettei tulos sisällä lainausmerkkejä
            string vendor = db.Lookup("AA:BB:CC:00:11:22");
            Assert.DoesNotContain("\"", vendor);
            Assert.Equal("Intel Corporation", vendor);
        }

        [Fact]
        public void Load_CommaInVendorName_ParsedCorrectly()
        {
            string path = WriteTempCsv("001122,\"Smith, John & Co.\"\n");
            var db = new OuiDatabase();
            db.LoadFromPath(path);
            Assert.Equal("Smith, John & Co.", db.Lookup("00:11:22:33:44:55"));
        }

        // ── Lookup ───────────────────────────────────────────────

        [Fact]
        public void Lookup_UnknownBssid_ReturnsUnknown()
        {
            var db = new OuiDatabase();
            db.LoadFromPath(WriteTempCsv("001122,TestVendor\n"));
            Assert.Equal("Unknown", db.Lookup("FF:FF:FF:FF:FF:FF"));
        }

        [Fact]
        public void Lookup_NullOrEmpty_ReturnsUnknown()
        {
            var db = new OuiDatabase();
            Assert.Equal("Unknown", db.Lookup(null));
            Assert.Equal("Unknown", db.Lookup(""));
            Assert.Equal("Unknown", db.Lookup("  "));
        }

        [Fact]
        public void Lookup_CaseInsensitive_Works()
        {
            string path = WriteTempCsv("AABBCC,TestVendor\n");
            var db = new OuiDatabase();
            db.LoadFromPath(path);
            Assert.Equal("TestVendor", db.Lookup("aa:bb:cc:00:11:22"));
            Assert.Equal("TestVendor", db.Lookup("AA:BB:CC:00:11:22"));
        }

        // ── Välimuisti ───────────────────────────────────────────

        [Fact]
        public void Lookup_CalledTwice_SameResult()
        {
            string path = WriteTempCsv("001122,CachedVendor\n");
            var db = new OuiDatabase();
            db.LoadFromPath(path);
            string r1 = db.Lookup("00:11:22:33:44:55");
            string r2 = db.Lookup("00:11:22:33:44:55");
            Assert.Equal(r1, r2);
        }

        [Fact]
        public void InvalidateCache_ThenLookup_StillWorks()
        {
            string path = WriteTempCsv("001122,VendorX\n");
            var db = new OuiDatabase();
            db.LoadFromPath(path);
            db.Lookup("00:11:22:33:44:55");          // täytä välimuisti
            db.InvalidateCache("00:11:22:33:44:55");  // tyhjennä
            Assert.Equal("VendorX", db.Lookup("00:11:22:33:44:55")); // lataa uudelleen
        }

        // ── Apufunktiot ───────────────────────────────────────────

        private static string WriteTempCsv(string content)
        {
            string path = Path.GetTempFileName() + ".csv";
            File.WriteAllText(path, content, System.Text.Encoding.UTF8);
            return path;
        }
    }
}
