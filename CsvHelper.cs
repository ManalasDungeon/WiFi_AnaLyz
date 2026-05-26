using System;

namespace WifiAnalyzerPro
{
    public static class CsvHelper
    {
        /// <summary>RFC-4180-yhteensopiva CSV-pakotusfunktio.</summary>
        public static string Escape(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            bool needsQuote = s.IndexOf(',') >= 0 || s.IndexOf('"') >= 0 ||
                              s.IndexOf('\n') >= 0 || s.IndexOf('\r') >= 0;
            if (!needsQuote) return s;
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        }

        /// <summary>Muodostaa pilkulla erotetun rivin jo pakotettujen kenttien listasta.</summary>
        public static string Row(params string[] fields)
            => string.Join(",", fields);
    }
}
