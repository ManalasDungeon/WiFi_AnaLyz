using System;
using System.Collections.Generic;
using System.Text;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Generoi WiFi-QR-koodin ja renderöi sen konsoliin Unicode-lohkomerkeillä.
    /// Toteutettu puhtaassa C#:ssa ilman ulkoisia riippuvuuksia.
    /// Tukee Version 2–10 QR-koodeja (M-tason virheenkorjaus).
    /// </summary>
    public static class WifiQrCode
    {
        // ── Julkinen API ──────────────────────────────────────────

        /// <summary>
        /// Näyttää WiFi-QR-koodin konsolissa.
        /// Pyytää salasanan turvallisesti piilotetulla syötöllä.
        /// </summary>
        public static void ShowInConsole(string ssid, string security)
        {
            Console.WriteLine();
            Console.WriteLine($"  QR-koodi verkolle: {ssid}");
            Console.Write("  Salasana (piilossa, Enter = tyhjä): ");
            string password = ReadMasked();

            string authType = MapSecurity(security);
            string payload  = BuildWifiPayload(ssid, password, authType);

            try
            {
                bool[,] matrix = Generate(payload);
                RenderToConsole(matrix);
                Console.WriteLine();
                Console.WriteLine($"  WIFI:{authType};S:{ssid};...");
                Console.WriteLine("  Skannaa puhelimella → liittyy suoraan verkkoon.");
                Console.WriteLine("  Paina Enter jatkaaksesi...");
                try { Console.ReadLine(); } catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  QR-virhe: {ex.Message}");
                Console.WriteLine($"  Payload: {payload}");
            }
        }

        // ── WiFi-payload ─────────────────────────────────────────

        public static string BuildWifiPayload(string ssid, string password, string authType)
        {
            // Standardi: WIFI:T:<auth>;S:<ssid>;P:<password>;;
            // Erikoismerkit pakotetaan backslash-escaping:lla
            static string Esc(string s) => s == null ? "" :
                s.Replace("\\","\\\\").Replace(";","\\;").Replace(",","\\,")
                 .Replace("\"","\\\"").Replace(":","\\:");
            return $"WIFI:T:{authType};S:{Esc(ssid)};P:{Esc(password)};;";
        }

        private static string MapSecurity(string sec) =>
            (sec ?? "").Contains("3") ? "WPA" :
            (sec ?? "").Contains("Ent") ? "WPA" :
            (sec ?? "").Contains("2") ? "WPA" :
            (sec ?? "") == "WPA" ? "WPA" :
            (sec ?? "") == "WEP" ? "WEP" : "nopass";

        private static string ReadMasked()
        {
            var sb = new StringBuilder();
            try
            {
                while (true)
                {
                    var k = Console.ReadKey(intercept: true);
                    if (k.Key == ConsoleKey.Enter) break;
                    if (k.Key == ConsoleKey.Backspace && sb.Length > 0) { sb.Remove(sb.Length-1,1); Console.Write("\b \b"); }
                    else if (k.KeyChar >= 32) { sb.Append(k.KeyChar); Console.Write('*'); }
                }
            }
            catch { }
            Console.WriteLine();
            return sb.ToString();
        }

        // ── QR-koodin generointi ──────────────────────────────────

        // GF(256) = GF(2^8) primitiivipolynomi x^8+x^4+x^3+x^2+1 = 0x11D
        private static readonly byte[] _gfExp = new byte[512];
        private static readonly byte[] _gfLog = new byte[256];

        static WifiQrCode()
        {
            int x = 1;
            for (int i = 0; i < 255; i++)
            {
                _gfExp[i] = (byte)x;
                _gfLog[x] = (byte)i;
                x <<= 1;
                if ((x & 0x100) != 0) x ^= 0x11D;
            }
            for (int i = 255; i < 512; i++) _gfExp[i] = _gfExp[i - 255];
        }

        private static byte GfMul(byte a, byte b)
        {
            if (a == 0 || b == 0) return 0;
            return _gfExp[(_gfLog[a] + _gfLog[b]) % 255];
        }

        // Version M-tason ECC:
        // v: dataCW, ecCW, size (=(v-1)*4+21)
        private static readonly (int dataCW, int ecCW, int size)[] _versionInfo =
        {
            (0,0,0),       // dummy v0
            (0,0,21),      // v1  — ei tueta (ei riittävästi tilaa)
            (16,10,25),    // v2  — max ~14 B data
            (26,15,29),    // v3  — max ~23 B
            (36,20,33),    // v4  — max ~31 B
            (46,26,37),    // v5  — max ~40 B
            (60,18,41),    // v6  — max ~51 B (2 EC-lohkoa)
            (66,20,45),    // v7  — max ~57 B
            (86,24,49),    // v8  — max ~74 B
            (100,30,53),   // v9  — max ~85 B
            (122,18,57),   // v10 — max ~104 B (2 EC-lohkoa)
        };

        // Alignment pattern keskukset per versio (versio 2+)
        private static readonly int[][] _alignPos =
        {
            null,null,          // v0,v1
            new[]{18},          // v2
            new[]{22},          // v3
            new[]{26},          // v4
            new[]{30},          // v5
            new[]{34},          // v6
            new[]{6,22,38},     // v7
            new[]{6,24,42},     // v8
            new[]{6,26,46},     // v9
            new[]{6,28,50},     // v10
        };

        public static bool[,] Generate(string data)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(data);

            // Valitse versio datan pituuden mukaan
            int ver = SelectVersion(bytes.Length);
            if (ver < 0) throw new InvalidOperationException(
                $"Data liian pitkä QR-koodille (max ~100 B): {bytes.Length} B");

            var (dataCW, ecCW, size) = _versionInfo[ver];

            // Koodaa data (byte mode)
            var dataBits = EncodeBytes(bytes, dataCW * 8);

            var ecPoly = BuildEcPoly(ecCW);
            var dataBytes = new byte[dataCW];
            for (int i = 0; i < dataCW; i++)
            {
                byte b = 0;
                for (int bit = 0; bit < 8 && i * 8 + bit < dataBits.Count; bit++)
                    if (dataBits[i * 8 + bit]) b |= (byte)(1 << (7 - bit));
                dataBytes[i] = b;
            }
            var ecBytes = ReedSolomon(dataBytes, ecPoly);

            // Yhdistä kaikki bitit
            var allBits  = new List<bool>(dataBits);
            foreach (var b in ecBytes)
                for (int i = 7; i >= 0; i--) allBits.Add((b >> i & 1) == 1);

            // Rakenna moduulimatriisi
            bool[,] matrix = new bool[size, size];
            bool[,] fixed_  = new bool[size, size]; // onko moduuli kiinnitetty

            PlaceFinder(matrix, fixed_, 0, 0, size);
            PlaceFinder(matrix, fixed_, size-7, 0, size);
            PlaceFinder(matrix, fixed_, 0, size-7, size);
            PlaceTiming(matrix, fixed_, size);
            if (ver >= 2) PlaceAlignment(matrix, fixed_, ver, size);
            PlaceFormatDummy(matrix, fixed_, size);

            // Kirjoita data paras maski käyttäen
            int bestMask = 0; int bestPenalty = int.MaxValue;
            bool[,] bestMatrix = null;
            for (int m = 0; m < 8; m++)
            {
                var candidate = (bool[,])matrix.Clone();
                PlaceData(candidate, fixed_, allBits, size, m);
                PlaceFormat(candidate, size, ver, m);
                int penalty = EvalPenalty(candidate, size);
                if (penalty < bestPenalty) { bestPenalty = penalty; bestMask = m; bestMatrix = candidate; }
            }
            return bestMatrix;
        }

        private static int SelectVersion(int byteLen)
        {
            // Tarvittava dataCW lasketaan tarkasti byte-moodille (versiot 1–9):
            // mode(4) + char_count(8) + data(8*n) + terminator(4) → pyöristettynä ylös tavuihin
            int needed = byteLen + 2; // ceil((12 + 8*n + 4) / 8) = n + 2
            for (int v = 2; v <= 10; v++)
                if (_versionInfo[v].dataCW >= needed) return v;
            return -1;
        }

        private static List<bool> EncodeBytes(byte[] data, int totalBits)
        {
            var bits = new List<bool>(totalBits + 16);
            // Mode indicator: byte mode = 0100
            bits.AddRange(new[]{false,true,false,false});
            // Pituus (8 bittiä versioille 1-9)
            int len = data.Length;
            for (int i = 7; i >= 0; i--) bits.Add((len >> i & 1) == 1);
            // Data
            foreach (byte b in data)
                for (int i = 7; i >= 0; i--) bits.Add((b >> i & 1) == 1);
            // Lopettaja (max 4 nollaa)
            int term = Math.Min(4, totalBits - bits.Count);
            for (int i = 0; i < term; i++) bits.Add(false);
            // Tasaa tavurajalle
            while (bits.Count % 8 != 0) bits.Add(false);
            // Täytetavut
            bool pad = true;
            while (bits.Count < totalBits)
            {
                foreach (bool b in pad ? new[]{true,true,true,false,true,true,false,false}
                                       : new[]{false,false,false,true,false,false,false,true})
                    if (bits.Count < totalBits) bits.Add(b);
                pad = !pad;
            }
            return bits;
        }

        private static byte[] BuildEcPoly(int ecCW)
        {
            byte[] g = {1};
            for (int i = 0; i < ecCW; i++)
            {
                byte alpha = _gfExp[i];
                var ng = new byte[g.Length + 1];
                for (int j = 0; j < g.Length; j++)
                {
                    ng[j]   ^= GfMul(g[j], alpha);
                    ng[j+1] ^= g[j];
                }
                g = ng;
            }
            return g;
        }

        private static byte[] ReedSolomon(byte[] msg, byte[] gen)
        {
            var r = new byte[msg.Length + gen.Length - 1];
            Array.Copy(msg, r, msg.Length);
            for (int i = 0; i < msg.Length; i++)
            {
                byte c = r[i];
                if (c == 0) continue;
                for (int j = 1; j < gen.Length; j++)
                    r[i+j] ^= GfMul(gen[j], c);
            }
            var ec = new byte[gen.Length - 1];
            Array.Copy(r, msg.Length, ec, 0, ec.Length);
            return ec;
        }

        // ── Moduulisijoittelu ─────────────────────────────────────

        private static void PlaceFinder(bool[,] m, bool[,] f, int row, int col, int size)
        {
            // 7x7 finder + 1 separator
            for (int r = -1; r <= 7; r++)
                for (int c2 = -1; c2 <= 7; c2++)
                {
                    int rr = row+r, cc = col+c2;
                    if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue;
                    // Reuna (r/c2 = 0 tai 6) tai sisäneliö (r 2–4, c2 2–4)
                    bool on = (r==0||r==6||c2==0||c2==6) || (r>=2&&r<=4&&c2>=2&&c2<=4);
                    // separator row/col
                    if (r == -1 || r == 7 || c2 == -1 || c2 == 7) on = false;
                    m[rr,cc] = on; f[rr,cc] = true;
                }
        }

        private static void PlaceTiming(bool[,] m, bool[,] f, int size)
        {
            for (int i = 8; i < size-8; i++)
            {
                bool on = (i % 2 == 0);
                if (!f[6,i]) { m[6,i]=on; f[6,i]=true; }
                if (!f[i,6]) { m[i,6]=on; f[i,6]=true; }
            }
        }

        private static void PlaceAlignment(bool[,] m, bool[,] f, int ver, int size)
        {
            if (ver < 2 || _alignPos[ver] == null) return;
            var pos = _alignPos[ver];
            foreach (int cr in pos)
                foreach (int cc in pos)
                {
                    if (f[cr,cc]) continue; // päällekkäin finder:in kanssa
                    for (int dr=-2;dr<=2;dr++) for (int dc=-2;dc<=2;dc++)
                    {
                        bool on=(dr==-2||dr==2||dc==-2||dc==2)||
                                (dr==0&&dc==0);
                        m[cr+dr,cc+dc]=on; f[cr+dr,cc+dc]=true;
                    }
                }
        }

        private static void PlaceFormatDummy(bool[,] m, bool[,] f, int size)
        {
            // Varaa format-infon paikat (täytetään myöhemmin PlaceFormat:ssa)
            int[] fmtRows = {0,1,2,3,4,5,7,8};
            for (int i = 0; i < 8; i++) { if(!f[fmtRows[i],8]) f[fmtRows[i],8]=true; }
            for (int i = 0; i < 8; i++) { if(!f[8,i]) f[8,i]=true; }
            for (int i = 0; i < 8; i++) { if(!f[size-1-i,8]) f[size-1-i,8]=true; }
            for (int i = 0; i < 8; i++) { if(!f[8,size-1-i]) f[8,size-1-i]=true; }
            m[size-8,8]=true; f[size-8,8]=true; // dark module
        }

        private static void PlaceData(bool[,] m, bool[,] f, List<bool> bits, int size, int mask)
        {
            int idx = 0;
            bool up = true;
            for (int col = size-1; col >= 1; col -= 2)
            {
                if (col == 6) col--; // ohita timing-sarake
                for (int r = 0; r < size; r++)
                {
                    int row = up ? size-1-r : r;
                    for (int dc = 0; dc <= 1; dc++)
                    {
                        int c = col - dc;
                        if (f[row,c]) continue;
                        bool bit = idx < bits.Count && bits[idx++];
                        bool masked = ApplyMask(mask, row, c) ? !bit : bit;
                        m[row,c] = masked;
                    }
                }
                up = !up;
            }
        }

        private static bool ApplyMask(int mask, int row, int col) => mask switch
        {
            0 => (row+col)%2==0,
            1 => row%2==0,
            2 => col%3==0,
            3 => (row+col)%3==0,
            4 => (row/2+col/3)%2==0,
            5 => (row*col)%2+(row*col)%3==0,
            6 => ((row*col)%2+(row*col)%3)%2==0,
            7 => ((row+col)%2+(row*col)%3)%2==0,
            _ => false
        };

        private static void PlaceFormat(bool[,] m, int size, int ver, int mask)
        {
            // EC level M = 00, mask 3 bits → format info = 5 bit number
            // Formattitieto: 2 bit EC + 3 bit mask → 5 bittiä → laajennettuna 15 bittiä
            int fmt = (0b00 << 3) | mask;  // EC=M(00), mask
            fmt = BchFormat(fmt);
            fmt ^= 0b101010000010010; // XOR maski

            // Sijoita formattibitit kahteen paikkaan
            int[] order = {0,1,2,3,4,5,7,8,  // sarake 8 / rivi 8
                           8,7,5,4,3,2,1,0};  // rivi 8 / sarake 8
            for (int i = 0; i < 15; i++)
            {
                bool bit = ((fmt >> i) & 1) == 1;
                // Vasen/yläkulma
                if (i < 8)      m[i < 6 ? i : i+1, 8]    = bit;
                else            m[8, i < 9 ? 7-i+8 : 14-i+1] = bit;
                // Oikea/alaosa
                if (i < 7)      m[size-1-i, 8]             = bit;
                else            m[8, size-7+(i-7)]          = bit;
            }
        }

        private static int BchFormat(int data)
        {
            int gen = 0x537;
            int d = data << 10;
            for (int i = 14; i >= 10; i--)
                if ((d >> i & 1) != 0) d ^= gen << (i-10);
            return (data << 10) | d;
        }

        private static int EvalPenalty(bool[,] m, int size)
        {
            int p = 0;
            // Sääntö 1: 5+ peräkkäistä samanväristä
            for (int r=0;r<size;r++) { int run=1; for(int c=1;c<size;c++) { if(m[r,c]==m[r,c-1]) run++; else run=1; if(run==5)p+=3; else if(run>5)p++; } }
            for (int c=0;c<size;c++) { int run=1; for(int r=1;r<size;r++) { if(m[r,c]==m[r-1,c]) run++; else run=1; if(run==5)p+=3; else if(run>5)p++; } }
            // Sääntö 2: 2x2 lohkot
            for (int r=0;r<size-1;r++) for(int c=0;c<size-1;c++)
                if(m[r,c]==m[r,c+1]&&m[r,c]==m[r+1,c]&&m[r,c]==m[r+1,c+1]) p+=3;
            // Sääntö 3: Finder-kuvio rivi/sarakkeessa (1011101 + 4 vaaleaa tai toisin päin)
            int[] pat = {1,0,1,1,1,0,1};
            for (int r=0;r<size;r++) for(int c=0;c<=size-7;c++)
            {
                bool match = true;
                for (int i=0;i<7;i++) if ((m[r,c+i]?1:0) != pat[i]) { match=false; break; }
                if (match && (c+7<=size-4 && !m[r,c+7]&&!m[r,c+8]&&!m[r,c+9]&&!m[r,c+10])) p+=40;
                if (match && (c>=4 && !m[r,c-1]&&!m[r,c-2]&&!m[r,c-3]&&!m[r,c-4]))          p+=40;
            }
            for (int c=0;c<size;c++) for(int r=0;r<=size-7;r++)
            {
                bool match = true;
                for (int i=0;i<7;i++) if ((m[r+i,c]?1:0) != pat[i]) { match=false; break; }
                if (match && (r+7<=size-4 && !m[r+7,c]&&!m[r+8,c]&&!m[r+9,c]&&!m[r+10,c])) p+=40;
                if (match && (r>=4 && !m[r-1,c]&&!m[r-2,c]&&!m[r-3,c]&&!m[r-4,c]))          p+=40;
            }
            // Sääntö 4: Tumman ja vaalean moduulin suhde — sakko kaukana 50%:sta
            int dark = 0;
            for (int r=0;r<size;r++) for(int c=0;c<size;c++) if (m[r,c]) dark++;
            int pct = dark * 100 / (size * size);
            int prev5 = pct / 5 * 5; int next5 = prev5 + 5;
            p += Math.Min(Math.Abs(prev5 - 50), Math.Abs(next5 - 50)) / 5 * 10;
            return p;
        }

        // ── Konsolirenderointi ────────────────────────────────────

        private static void RenderToConsole(bool[,] matrix)
        {
            int size = matrix.GetLength(0);
            const int border = 2; // hiljainen alue (4 moduulia spec:n mukaan, käytämme 2)

            Console.WriteLine();
            var sb = new StringBuilder();
            // Yläreuna
            for (int b = 0; b < border; b++) { sb.Append("  "); for (int c = 0; c < size + border*2; c++) sb.Append("  "); sb.AppendLine(); }

            // Piirretään kaksi riviä kerrallaan puoli-lohkomerkeillä (▀▄█ )
            for (int r = 0; r < size; r += 2)
            {
                sb.Append("  ");
                for (int b = 0; b < border; b++) sb.Append("██");
                for (int c = 0; c < size; c++)
                {
                    bool top = matrix[r, c];
                    bool bot = (r+1 < size) && matrix[r+1, c];
                    sb.Append(
                        top && bot  ? "  " :   // molemmat mustia (musta tausta = tyhjä)
                        top         ? "▄▄" :   // vain yläpuoli musta
                        bot         ? "▀▀" :   // vain alapuoli musta
                                      "██");   // molemmat tyhjiä (= valkoinen)
                }
                for (int b = 0; b < border; b++) sb.Append("██");
                sb.AppendLine();
            }
            // Alareuna
            for (int b = 0; b < border; b++) { sb.Append("  "); for (int c = 0; c < size + border*2; c++) sb.Append("  "); sb.AppendLine(); }

            Console.Write(sb);
        }
    }
}
