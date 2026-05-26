using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// DPI-analyysi: tunnettujen palveluiden tunnistus ja blacklist-tarkistus.
    ///
    /// Palvelutunnistus: 30+ palvelua domenikuvioiden perusteella.
    /// Blacklist:
    ///   - Sisäänrakennettu lista (C2, cryptomining, Mirai, phishing)
    ///   - Ulkoinen tiedosto (blacklist.txt), yksi domain/pattern per rivi
    ///   - Kategorisoitu vakavuustaso (1=tracking, 2=suspicious, 3=malware/C2)
    ///
    /// Säikeenturvallisuus: vain luku-operaatioita julkisessa API:ssa.
    /// Blacklist ladataan kerran käynnistyksen yhteydessä; tiedoston
    /// muutokset vaativat uudelleenkäynnistyksen.
    /// </summary>
    public class DpiAnalyzer
    {
        // ── Palvelutunnistus ──────────────────────────────────────

        private static readonly (string[] Patterns, string Label)[] ServiceRules =
        {
            // Suoratoisto
            new(new[]{"netflix.com","nflxvideo","nflximg","netflixdnstest"}, "Netflix"),
            new(new[]{"youtube.com","youtu.be","googlevideo.com","yt3.ggpht"}, "YouTube"),
            new(new[]{"spotify.com","spotifycdn","scdn.co"}, "Spotify"),
            new(new[]{"twitch.tv","twitchapps.com","jtvnw.net"}, "Twitch"),
            new(new[]{"disneyplus.com","disneystreaming","bamgrid.com"}, "Disney+"),
            new(new[]{"hbomax.com","max.com","hbo.com"}, "HBO Max"),
            new(new[]{"primevideo.com","amazon.com/gp/video","aiv-cdn"}, "Prime Video"),
            // Pilvipalvelut
            new(new[]{"icloud.com","apple.com","appleid.apple","mzstatic.com"}, "Apple"),
            new(new[]{"google.com","googleapis.com","googleusercontent","gstatic.com"}, "Google"),
            new(new[]{"microsoft.com","office.com","office365.com","live.com","microsoftonline"}, "Microsoft"),
            new(new[]{"windowsupdate.com","update.microsoft","wns.windows.com"}, "Windows Update"),
            new(new[]{"dropbox.com","dropboxstatic"}, "Dropbox"),
            new(new[]{"onedrive.com","sharepoint.com"}, "OneDrive"),
            new(new[]{"drive.google.com"}, "Google Drive"),
            // Sosiaalinen media
            new(new[]{"facebook.com","fbcdn.net","fb.com"}, "Facebook"),
            new(new[]{"instagram.com","cdninstagram.com"}, "Instagram"),
            new(new[]{"twitter.com","x.com","twimg.com","t.co"}, "Twitter/X"),
            new(new[]{"tiktok.com","tiktokcdn.com","musical.ly"}, "TikTok"),
            new(new[]{"linkedin.com","licdn.com"}, "LinkedIn"),
            new(new[]{"reddit.com","redd.it","redditmedia.com","reddituploads"}, "Reddit"),
            // Viestintä
            new(new[]{"discord.com","discordapp.com","discord.gg"}, "Discord"),
            new(new[]{"slack.com","slack-edge","slack-imgs"}, "Slack"),
            new(new[]{"whatsapp.com","whatsapp.net"}, "WhatsApp"),
            new(new[]{"telegram.org","t.me"}, "Telegram"),
            new(new[]{"zoom.us","zoom.com","zoomgov.com"}, "Zoom"),
            new(new[]{"teams.microsoft.com","teams.live.com"}, "Teams"),
            // Pelit
            new(new[]{"steam","valve","steampowered.com"}, "Steam"),
            new(new[]{"epicgames.com","unrealengine"}, "Epic Games"),
            new(new[]{"playstation.com","psn.com","sony.com"}, "PlayStation"),
            new(new[]{"xbox.com","xboxlive.com"}, "Xbox"),
            // CDN / Infra
            new(new[]{"cloudflare.com","cloudflare-dns","1.1.1.1"}, "Cloudflare"),
            new(new[]{"akamai","akamaized","akamaitechnologies"}, "Akamai CDN"),
            new(new[]{"amazonaws.com","aws.amazon.com","cloudfront.net"}, "AWS"),
            new(new[]{"azure.com","azureedge","azurewebsites"}, "Azure"),
            new(new[]{"fastly.com","fastlylb.net"}, "Fastly CDN"),
        };

        // ── Blacklist ─────────────────────────────────────────────

        /// <summary>Blacklist-osuma: domain, vakavuus (1–3), syy.</summary>
        public sealed class BlacklistHit
        {
            public string Domain   { get; set; }
            public int    Severity { get; set; }  // 1=tracking 2=suspicious 3=malware/C2
            public string Reason   { get; set; }
        }

        // Sisäänrakennettu blacklist: (pattern, severity, reason)
        private static readonly (string Pattern, int Severity, string Reason)[] BuiltinBlacklist =
        {
            // ── C2 / Malware ─────────────────────────────────────
            ("freshdesk-support-service.com", 3, "Trickbot C2"),
            ("feodot.com",                    3, "Feodo banker C2"),
            ("emotet",                        3, "Emotet malware pattern"),
            ("qakbot",                        3, "QakBot malware pattern"),
            ("cobalt-strike",                 3, "CobaltStrike C2 indicator"),
            ("meterpreter",                   3, "Metasploit C2 indicator"),
            ("dnscat",                        3, "DNS C2 tunneling tool"),
            ("iodine",                        3, "DNS tunnel (iodine)"),
            ("burpcollaborator.net",          2, "Burp Suite OAST (pentest/exfil)"),
            ("interactsh.com",                2, "OOB interaction (pentest/exfil)"),
            ("canarytokens.com",              2, "Canary token / honeytoken"),
            // ── Cryptomining ──────────────────────────────────────
            ("xmrig.com",                     3, "XMRig miner"),
            ("coinhive.com",                  3, "Coinhive cryptominer (deprecated)"),
            ("cryptonight",                   3, "Cryptomining pool pattern"),
            ("moneropool.com",                3, "Monero mining pool"),
            ("2miners.com",                   3, "Cryptomining pool"),
            ("nanopool.org",                  3, "Cryptomining pool"),
            ("f2pool.com",                    3, "Cryptomining pool"),
            ("mining.pool",                   3, "Generic mining pool pattern"),
            // ── IoT-botnet (Mirai-variantit) ─────────────────────
            ("cnc.mirai",                     3, "Mirai botnet C2"),
            ("sora.mirai",                    3, "Mirai Sora variant C2"),
            ("botnet-",                       3, "Botnet C2 pattern"),
            ("tr069.cgi",                     3, "TR-069 exploit indicator"),
            // ── DNS-tunneling ──────────────────────────────────────
            (".b32.i2p",                      2, "I2P anonymity network"),
            (".onion.ly",                     2, "Tor hidden service proxy"),
            ("dns2tcp",                       3, "DNS tunneling (dns2tcp)"),
            ("tcp-over-dns",                  3, "DNS tunneling indicator"),
            // ── Phishing / typosquatting ──────────────────────────
            ("rn0.ru",                        3, "Known phishing infrastructure"),
            ("trackingprotect",               1, "Tracking protection bypass"),
            // ── Aggressiivinen mainosseuranta ─────────────────────
            ("doubleclick.net",               1, "Google ad tracking"),
            ("scorecardresearch.com",         1, "ComScore tracking"),
            ("omtrdc.net",                    1, "Adobe tracking"),
            ("demdex.net",                    1, "Adobe Audience Manager tracking"),
        };

        private readonly HashSet<string> _customBlacklist = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<(string Pattern, int Severity, string Reason)> _allBlacklist;
        private volatile string _status = "DPI: ei blacklistiä ladattu";

        public string Status => _status;

        public DpiAnalyzer(string blacklistPath = "blacklist.txt")
        {
            _allBlacklist = new List<(string, int, string)>(BuiltinBlacklist);
            LoadExternalBlacklist(blacklistPath);
            _status = $"DPI: {_allBlacklist.Count} blacklist-kuvia, {ServiceRules.Length} palvelua";
        }

        private void LoadExternalBlacklist(string path)
        {
            if (!File.Exists(path)) return;
            try
            {
                int added = 0;
                foreach (var rawLine in File.ReadAllLines(path))
                {
                    var line = rawLine.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#")) continue;
                    // Formaatti: domain [TAB severity [TAB reason]]
                    var parts = line.Split('\t');
                    string pattern = parts[0].Trim().ToLowerInvariant();
                    int sev  = parts.Length > 1 && int.TryParse(parts[1].Trim(), out int s) ? s : 2;
                    string r = parts.Length > 2 ? parts[2].Trim() : "Ulkoinen blacklist";
                    _allBlacklist.Add((pattern, sev < 1 ? 1 : sev > 3 ? 3 : sev, r));
                    added++;
                }
                AppLogger.Log($"[DPI] Blacklist: ladattu {added} omaa merkintää ({path})");
            }
            catch (Exception ex) { AppLogger.Log($"[DPI] Blacklist latausvirhe: {ex.Message}"); }
        }

        // ── Julkinen API ──────────────────────────────────────────

        /// <summary>
        /// Tunnistaa palvelun ja tarkistaa blacklistin yhdellä kutsulla.
        /// Palauttaa tuple: (palvelunimi tai null, blacklist-osuma tai null).
        /// </summary>
        public (string ServiceName, BlacklistHit Hit) Analyze(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return (null, null);

            string lower = domain.ToLowerInvariant();
            string svc   = MatchService(lower);
            var    hit   = CheckBlacklist(lower);
            return (svc, hit);
        }

        private string MatchService(string lower)
        {
            foreach (var rule in ServiceRules)
                foreach (var pat in rule.Patterns)
                    if (lower.Contains(pat)) return rule.Label;
            return null;
        }

        private BlacklistHit CheckBlacklist(string lower)
        {
            foreach (var (pattern, sev, reason) in _allBlacklist)
                if (lower.Contains(pattern))
                    return new BlacklistHit { Domain = lower, Severity = sev, Reason = reason };
            return null;
        }

        /// <summary>Vakavuusteksti käyttöliittymää varten.</summary>
        public static string SeverityLabel(int sev) => sev switch
        {
            3 => "KRIITTINEN",
            2 => "Epäilyttävä",
            _ => "Seuranta"
        };
    }
}
