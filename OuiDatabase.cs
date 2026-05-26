using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// OUI-valmistajatietokanta. Lataa oui.csv kerran ja välimuistittaa hakutulokset.
    /// </summary>
    public class OuiDatabase
    {
        private readonly Dictionary<string, string>          _ouiVendors  = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, string> _vendorCache = new(StringComparer.OrdinalIgnoreCase);
        private volatile bool   _loaded;
        private volatile string _status = "OUI: ei ladattu";
        private readonly object _loadLock = new object();

        public string Status => _status;

        /// <summary>
        /// Testattavuusrajapinta: lataa OUI-data suoraan annetusta polusta.
        /// Tuotantokoodissa käytetään LoadIfNeeded().
        /// </summary>
        public void LoadFromPath(string path)
        {
            lock (_loadLock)
            {
                _ouiVendors.Clear();
                _vendorCache.Clear();
                if (!File.Exists(path))
                {
                    _status = "OUI: tiedostoa ei löydy";
                    _loaded = true;
                    return;
                }
                try
                {
                    int count = 0;
                    using var sr = new StreamReader(path);
                    string header = sr.ReadLine() ?? "";
                    if (!LooksLikeHeader(header)) ParseLine(header, ref count);
                    while (!sr.EndOfStream) ParseLine(sr.ReadLine(), ref count);
                    _status = $"OUI: ladattu {count} valmistajaa";
                }
                catch (Exception ex) { _status = $"OUI: virhe: {ex.Message}"; }
                finally { _loaded = true; }
            }
        }
        public void LoadIfNeeded()
        {
            if (_loaded) return; // nopea tarkistus ilman lukkoa
            lock (_loadLock)
            {
                if (_loaded) return; // tarkista uudelleen lukon sisällä (double-checked locking)
                string[] candidates = {
                    Path.Combine(AppContext.BaseDirectory, "oui.csv"),
                    Path.Combine(AppContext.BaseDirectory, "oui_simple.csv"),
                };
                string found = Array.Find(candidates, File.Exists);
                if (found == null) { _status = "OUI: ei löydy (oui.csv puuttuu)"; _loaded = true; return; }
                try
                {
                    int count = 0;
                    using var sr = new StreamReader(found);
                    string header = sr.ReadLine() ?? "";
                    if (!LooksLikeHeader(header)) ParseLine(header, ref count);
                    while (!sr.EndOfStream) ParseLine(sr.ReadLine(), ref count);
                    _status = $"OUI: ladattu {count} valmistajaa ({Path.GetFileName(found)})";
                }
                catch (Exception ex) { _status = $"OUI: lataus epäonnistui: {ex.Message}"; }
                finally { _loaded = true; }
            }
        }

        public string Lookup(string bssid)
        {
            if (string.IsNullOrWhiteSpace(bssid)) return "Unknown";
            return _vendorCache.GetOrAdd(bssid, b =>
            {
                LoadIfNeeded();
                string oui = Normalize(b);
                return oui.Length == 6 && _ouiVendors.TryGetValue(oui, out var v) ? v : "Unknown";
            });
        }

        public void InvalidateCache(string bssid)
        {
            if (bssid != null) _vendorCache.TryRemove(bssid, out _);
        }

        /// <summary>Palauttaa MAC-osoitteen ensimmäiset 6 heksadesimaalimerkkiä (OUI).</summary>
        public static string Normalize(string s)
        {
            if (s == null) return "";
            s = s.Trim().Trim('"').ToUpperInvariant()
                 .Replace(":", "").Replace("-", "").Replace(".", "").Replace(" ", "");
            return s.Length >= 6 ? s.Substring(0, 6) : s;
        }

        private void ParseLine(string line, ref int count)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            var parts = SplitCsv(line);
            if (parts.Count < 2) return;

            string prefix;
            string vendor;

            // Tuetaan molempia formaatteja:
            //
            // A) Yksinkertainen 2-sarakeformaatti (oui_simple.csv):
            //    AABBCC,Vendor Name
            //    AA:BB:CC,Vendor Name
            //
            // B) IEEE:n virallinen 4-sarakeformaatti (oui.csv IEEE:ltä):
            //    Registry,Assignment,Organization Name,Organization Address
            //    MA-L,0C0EF2,AVM GmbH,"AVM Audiovisuelles..."
            //    → parts[0]="MA-L"  parts[1]="0C0EF2"  parts[2]="AVM GmbH"

            string p0 = Normalize(parts[0]);
            if (p0.Length == 6)
            {
                // Formaatti A: ensimmäinen sarake on OUI-prefix
                prefix = p0;
                vendor = parts[1].Trim().Trim('"');
            }
            else if (parts.Count >= 3)
            {
                // Formaatti B: toinen sarake on OUI-prefix (esim. IEEE oui.csv)
                prefix = Normalize(parts[1]);
                vendor = parts[2].Trim().Trim('"');
                if (prefix.Length != 6) return;
            }
            else return;

            if (string.IsNullOrWhiteSpace(vendor)) return;
            if (!_ouiVendors.ContainsKey(prefix)) { _ouiVendors[prefix] = vendor; count++; }
        }

        private static bool LooksLikeHeader(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return true;
            var l = line.ToLowerInvariant();
            return l.Contains("assignment") || l.Contains("organization") ||
                   l.Contains("company")    || l.Contains("registry");
        }

        /// <summary>
        /// KORJAUS: Ei lisää lainausmerkkejä tulokseen.
        /// Alkuperäinen cur.Append(c) kun c=='"' aiheutti "Intel Corp" → "\"Intel Corp\"".
        /// </summary>
        private static List<string> SplitCsv(string line)
        {
            var list  = new List<string>();
            bool inQ  = false;
            var  cur  = new System.Text.StringBuilder();
            foreach (char c in line)
            {
                if      (c == '"')         inQ = !inQ;          // vain vaihda tila — ei lisätä "
                else if (c == ',' && !inQ) { list.Add(cur.ToString()); cur.Clear(); }
                else                       cur.Append(c);
            }
            list.Add(cur.ToString());
            return list;
        }
    }
}
