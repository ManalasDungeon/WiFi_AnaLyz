using Xunit;

namespace WifiAnalyzerPro.Tests
{
    public class CsvHelperTests
    {
        // ── Escape ───────────────────────────────────────────────

        [Fact]
        public void Escape_PlainText_NoQuotes()
        {
            Assert.Equal("Hello", CsvHelper.Escape("Hello"));
        }

        [Fact]
        public void Escape_Null_ReturnsEmpty()
        {
            Assert.Equal("", CsvHelper.Escape(null));
        }

        [Fact]
        public void Escape_EmptyString_ReturnsEmpty()
        {
            Assert.Equal("", CsvHelper.Escape(""));
        }

        [Fact]
        public void Escape_ContainsComma_Quoted()
        {
            string result = CsvHelper.Escape("Smith, John");
            Assert.Equal("\"Smith, John\"", result);
        }

        [Fact]
        public void Escape_ContainsQuote_DoubledAndQuoted()
        {
            // "He said "hello""  →  "He said ""hello"""
            string result = CsvHelper.Escape("He said \"hello\"");
            Assert.Equal("\"He said \"\"hello\"\"\"", result);
        }

        [Fact]
        public void Escape_ContainsNewline_Quoted()
        {
            string result = CsvHelper.Escape("line1\nline2");
            Assert.StartsWith("\"", result);
            Assert.EndsWith("\"", result);
        }

        [Fact]
        public void Escape_ContainsCR_Quoted()
        {
            string result = CsvHelper.Escape("a\rb");
            Assert.StartsWith("\"", result);
        }

        [Fact]
        public void Escape_NumbersOnly_NoQuotes()
        {
            Assert.Equal("12345", CsvHelper.Escape("12345"));
        }

        [Fact]
        public void Escape_SpecialCharsNoCommaOrQuote_NoQuotes()
        {
            // Piste, välilyönti, viiva — ei pilkkua tai lainausmerkkiä
            Assert.Equal("AVM GmbH", CsvHelper.Escape("AVM GmbH"));
        }

        [Fact]
        public void Escape_EscapedResult_RoundTripParseable()
        {
            // Varmista että escaping on palautuva:
            // Escapen tulos pitäisi voida "purkaa" poistamalla ulkoiset lainausmerkit
            // ja korvaamalla "" → "
            string input  = "He said, \"hello\"";
            string escaped = CsvHelper.Escape(input);
            // Poista ulkoiset lainausmerkit ja korvaa "" → "
            string unescaped = escaped.Substring(1, escaped.Length - 2)
                                      .Replace("\"\"", "\"");
            Assert.Equal(input, unescaped);
        }

        // ── Row ──────────────────────────────────────────────────

        [Fact]
        public void Row_TwoFields_JoinedWithComma()
        {
            Assert.Equal("a,b", CsvHelper.Row("a", "b"));
        }

        [Fact]
        public void Row_EmptyFields_CommaSeparated()
        {
            Assert.Equal(",", CsvHelper.Row("", ""));
        }

        [Fact]
        public void Row_SingleField_NoComma()
        {
            Assert.Equal("hello", CsvHelper.Row("hello"));
        }

        [Fact]
        public void Row_AlreadyEscapedFields_CorrectOutput()
        {
            string f1 = CsvHelper.Escape("Smith, John");
            string f2 = CsvHelper.Escape("42");
            string row = CsvHelper.Row(f1, f2);
            Assert.Equal("\"Smith, John\",42", row);
        }

        // ── Yhdistelmätestit ─────────────────────────────────────

        [Fact]
        public void Escape_WifiSsidWithSpecialChars_SafeForCsv()
        {
            // Tyypillinen WiFi SSID
            string ssid   = "Café, \"Open\" Network";
            string result = CsvHelper.Escape(ssid);
            // Tulee olla lainausmerkkien sisällä
            Assert.StartsWith("\"", result);
            Assert.EndsWith("\"", result);
            // Sisäiset lainausmerkit tulee olla kahdennettuja
            Assert.Contains("\"\"", result);
        }

        [Fact]
        public void Escape_BssidFormat_NotQuoted()
        {
            // MAC-osoite ei sisällä pilkkua → ei lainausmerkkejä
            Assert.Equal("AA:BB:CC:DD:EE:FF",
                CsvHelper.Escape("AA:BB:CC:DD:EE:FF"));
        }
    }
}
