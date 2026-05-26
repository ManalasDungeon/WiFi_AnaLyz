using System;
using System.Collections.Generic;
using System.Linq;

namespace WifiAnalyzerPro
{
    // ── Datatyypit ────────────────────────────────────────────────

    public enum ComplianceStatus { Pass, Fail, Warning, Info }

    public class ComplianceRule
    {
        public string           Id              { get; set; }
        public string           Standard        { get; set; }
        public string           Requirement     { get; set; }
        public string           Description     { get; set; }
        public ComplianceStatus Status          { get; set; }
        public string           Detail          { get; set; }
        public List<string>     AffectedBssids  { get; set; } = new();
    }

    public class ComplianceReport
    {
        public DateTime          GeneratedAt   { get; set; } = DateTime.Now;
        public List<ComplianceRule> Rules      { get; set; } = new();
        public string            OverallGrade  { get; set; }
        public int               PassCount     { get; set; }
        public int               FailCount     { get; set; }
        public int               WarnCount     { get; set; }
        public int               Score         { get; set; } // 0–100
    }

    /// <summary>
    /// Tarkistaa Wi-Fi-ympäristön vaatimustenmukaisuuden PCI-DSS 4.0
    /// ja ISO 27001:2022 -standardeja vasten.
    ///
    /// Tarkistettavat säännöt:
    ///
    ///   PCI-DSS 4.0:
    ///     4.2.1  — Ei WEP tai WPA1 -salauksia
    ///     4.2.1b — Ei avoimia verkkoja maksuympäristön läheisyydessä
    ///     2.2.7  — PMF (Protected Management Frames) pakotettu
    ///     11.2.2 — Rogue AP -tunnistus (Evil Twin -hälytykset)
    ///     11.2.1 — Deauth-hyökkäykset kirjattu
    ///     8.3.6  — WPA3 käyttöaste
    ///
    ///   ISO 27001:2022 A.8.20:
    ///     A.8.20-1 — Kaikilla AP:illa vähintään WPA2
    ///     A.8.20-2 — BSS Load -seuranta (kanavakuorma)
    ///     A.8.20-3 — Signaalivahvuuden laadunhallinta
    ///     A.8.20-4 — EAPOL-keräilyhyökkäysten tunnistus
    /// </summary>
    public static class ComplianceChecker
    {
        public static ComplianceReport Check(
            List<AnalyzedAccessPoint> aps,
            List<AlertEntry>          alerts,
            List<EapolTracker.EapolSummaryEntry> eapolSummary = null)
        {
            if (aps == null) aps = new List<AnalyzedAccessPoint>();
            if (alerts == null) alerts = new List<AlertEntry>();
            eapolSummary ??= new List<EapolTracker.EapolSummaryEntry>();

            var report = new ComplianceReport();
            var since24h = DateTime.Now.AddHours(-24);

            // ── PCI-DSS 4.2.1 — Ei WEP tai WPA1 ────────────────────
            {
                var insecure = aps.Where(a =>
                    a.Security == "WEP" || a.Security == "WPA" ||
                    a.Security == "Open").ToList();
                report.Rules.Add(new ComplianceRule
                {
                    Id = "PCI-4.2.1", Standard = "PCI-DSS 4.0",
                    Requirement = "Req 4.2.1 — Heikot salausprotokollat kielletty",
                    Description = "Kaikki langattomat siirtoyhteydet on salattava vahvalla algoritmilla. WEP, WPA (TKIP) ja avoimet verkot eivät täytä vaatimusta.",
                    Status      = insecure.Count == 0 ? ComplianceStatus.Pass : ComplianceStatus.Fail,
                    Detail      = insecure.Count == 0
                        ? "Kaikki havaitut AP:t käyttävät WPA2 tai WPA3."
                        : $"{insecure.Count} AP:ta käyttää heikkoa tai olematonta salausta: " +
                          string.Join(", ", insecure.Select(a => $"'{a.Ssid}' ({a.Security})")),
                    AffectedBssids = insecure.Select(a => a.Bssid).ToList()
                });
            }

            // ── PCI-DSS 4.2.1b — Ei avoimia verkkoja ────────────────
            {
                var open = aps.Where(a => a.Security == "Open").ToList();
                report.Rules.Add(new ComplianceRule
                {
                    Id = "PCI-4.2.1b", Standard = "PCI-DSS 4.0",
                    Requirement = "Req 4.2.1 — Avoimet verkot kielletty PCI-ympäristössä",
                    Description = "Maksukorttidataa käsittelevän ympäristön Wi-Fi-verkot eivät saa olla salaamattomia.",
                    Status      = open.Count == 0 ? ComplianceStatus.Pass : ComplianceStatus.Fail,
                    Detail      = open.Count == 0
                        ? "Avoimia verkkoja ei havaittu."
                        : $"{open.Count} avointa verkkoa: {string.Join(", ", open.Select(a => $"'{a.Ssid}'"))}",
                    AffectedBssids = open.Select(a => a.Bssid).ToList()
                });
            }

            // ── PCI-DSS 2.2.7 — PMF pakotettu ───────────────────────
            {
                var wpa2Plus = aps.Where(a =>
                    a.Security != null && (a.Security.Contains("2") || a.Security.Contains("3")))
                    .ToList();
                var noPmf = wpa2Plus.Where(a => !a.PmfRequired).ToList();
                ComplianceStatus st = noPmf.Count == 0 ? ComplianceStatus.Pass
                    : noPmf.Count <= wpa2Plus.Count / 2 ? ComplianceStatus.Warning
                    : ComplianceStatus.Fail;
                report.Rules.Add(new ComplianceRule
                {
                    Id = "PCI-2.2.7", Standard = "PCI-DSS 4.0",
                    Requirement = "Req 2.2.7 — Management Frame Protection vaaditaan",
                    Description = "PMF (802.11w / MFPR=1) estää Deauth-hyökkäykset. WPA3 asettaa tämän automaattisesti.",
                    Status      = st,
                    Detail      = noPmf.Count == 0
                        ? "Kaikki WPA2/WPA3-AP:t vaativat PMF:n."
                        : $"{noPmf.Count}/{wpa2Plus.Count} AP:ta ei vaadi PMF:ää: " +
                          string.Join(", ", noPmf.Take(5).Select(a => $"'{a.Ssid}'")),
                    AffectedBssids = noPmf.Select(a => a.Bssid).ToList()
                });
            }

            // ── PCI-DSS 11.2.2 — Rogue AP -tunnistus ────────────────
            {
                var evilAlerts = alerts
                    .Where(a => a.Type == "EvilTwin" && a.Time >= since24h).ToList();
                report.Rules.Add(new ComplianceRule
                {
                    Id = "PCI-11.2.2", Standard = "PCI-DSS 4.0",
                    Requirement = "Req 11.2.2 — Rogue AP -tunnistus ja -raportointi",
                    Description = "Ympäristön on tunnistettava luvattomat tukiasemat automaattisesti.",
                    Status      = ComplianceStatus.Info,
                    Detail      = evilAlerts.Count == 0
                        ? "Evil Twin -tunnistus aktiivinen. Ei hälytyksiä viimeisen 24 h aikana."
                        : $"HUOMIO: {evilAlerts.Count} Evil Twin -hälytystä viimeisen 24 h aikana. " +
                          "Tutki välittömästi.",
                    AffectedBssids = evilAlerts.Select(a => a.Bssid ?? "").Distinct().ToList()
                });
            }

            // ── PCI-DSS 11.2.1 — Deauth-hyökkäykset kirjattu ────────
            {
                var deauthAlerts = alerts
                    .Where(a => (a.Type == "DeauthStorm" || a.Type == "DeauthBroadcast")
                                && a.Time >= since24h).ToList();
                ComplianceStatus st = deauthAlerts.Count == 0
                    ? ComplianceStatus.Pass : ComplianceStatus.Warning;
                report.Rules.Add(new ComplianceRule
                {
                    Id = "PCI-11.2.1", Standard = "PCI-DSS 4.0",
                    Requirement = "Req 11.2.1 — Langattomat hyökkäykset kirjataan",
                    Description = "Deauth-hyökkäykset on tunnistettava ja kirjattava. Vaatii PMF-tuen torjuntaan.",
                    Status      = st,
                    Detail      = deauthAlerts.Count == 0
                        ? "Ei Deauth-hyökkäyksiä havaittu viimeisen 24 h aikana."
                        : $"{deauthAlerts.Count} Deauth-hyökkäystä 24 h — tarkista PMF-konfiguraatio.",
                    AffectedBssids = deauthAlerts.Select(a => a.Bssid ?? "").Distinct().ToList()
                });
            }

            // ── PCI-DSS 8.3.6 — WPA3 käyttöaste ─────────────────────
            {
                int total = aps.Count;
                int wpa3  = aps.Count(a => a.Security != null &&
                    (a.Security.Contains("3") || a.Security == "WPA2/3"));
                double pct = total > 0 ? wpa3 * 100.0 / total : 0;
                ComplianceStatus st = pct >= 80 ? ComplianceStatus.Pass
                    : pct >= 50 ? ComplianceStatus.Warning : ComplianceStatus.Info;
                report.Rules.Add(new ComplianceRule
                {
                    Id = "PCI-8.3.6", Standard = "PCI-DSS 4.0",
                    Requirement = "Req 8.3.6 — Vahvan salauksen käyttöaste",
                    Description = "WPA3 on suositeltava standardi uusiin asennuksiin. Tavoite: ≥80 % AP:ista.",
                    Status      = st,
                    Detail      = $"WPA3/WPA2+3: {wpa3}/{total} AP:ta ({pct:F0} %). " +
                        (pct < 80 ? "Harkitse WPA3:n käyttöönottoa uusissa laitteissa." : "Hyvä käyttöaste."),
                    AffectedBssids = aps.Where(a => a.Security == null || !a.Security.Contains("3"))
                        .Select(a => a.Bssid).ToList()
                });
            }

            // ── ISO 27001 A.8.20-1 — Kaikilla WPA2+ ─────────────────
            {
                var noWpa2 = aps.Where(a =>
                    a.Security == null || a.Security == "WEP" ||
                    a.Security == "WPA" || a.Security == "Open").ToList();
                report.Rules.Add(new ComplianceRule
                {
                    Id = "ISO-A.8.20-1", Standard = "ISO 27001:2022",
                    Requirement = "A.8.20 — Verkon turvallisuuden hallinta",
                    Description = "Kaikilla langattomilla tukiasemilla on oltava vähintään WPA2-salaus.",
                    Status      = noWpa2.Count == 0 ? ComplianceStatus.Pass : ComplianceStatus.Fail,
                    Detail      = noWpa2.Count == 0
                        ? "Kaikki AP:t WPA2 tai uudempi."
                        : $"{noWpa2.Count} AP:ta alle WPA2-tason.",
                    AffectedBssids = noWpa2.Select(a => a.Bssid).ToList()
                });
            }

            // ── ISO 27001 A.8.20-2 — Kanavakuorma < 80 % ────────────
            {
                var highLoad = aps.Where(a =>
                    a.ChannelUtilization.HasValue && a.ChannelUtilization.Value >= 80).ToList();
                ComplianceStatus st = highLoad.Count == 0 ? ComplianceStatus.Pass
                    : highLoad.Count <= 2 ? ComplianceStatus.Warning : ComplianceStatus.Fail;
                report.Rules.Add(new ComplianceRule
                {
                    Id = "ISO-A.8.20-2", Standard = "ISO 27001:2022",
                    Requirement = "A.8.20 — Verkon kapasiteetin hallinta",
                    Description = "Kanavakuorman (BSS Load IE 11) tulisi pysyä alle 80 % palvelutason ylläpitämiseksi.",
                    Status      = st,
                    Detail      = highLoad.Count == 0
                        ? "Kanavakuorma alle 80 % kaikilla mitatuilla AP:illa."
                        : $"{highLoad.Count} AP:ta yli 80 % kuormassa: " +
                          string.Join(", ", highLoad.Select(a => $"'{a.Ssid}' {a.ChannelUtilization}%")),
                    AffectedBssids = highLoad.Select(a => a.Bssid).ToList()
                });
            }

            // ── ISO 27001 A.8.20-3 — Signaalivahvuus ─────────────────
            {
                var weak = aps.Where(a => a.IsConnected && a.Rssi < -75).ToList();
                report.Rules.Add(new ComplianceRule
                {
                    Id = "ISO-A.8.20-3", Standard = "ISO 27001:2022",
                    Requirement = "A.8.20 — Signaalivahvuuden hallinta",
                    Description = "Yhdistetyn tukiaseman signaalivahvuuden tulisi olla yli -75 dBm luotettavan yhteyden takaamiseksi.",
                    Status      = weak.Count == 0 ? ComplianceStatus.Pass : ComplianceStatus.Warning,
                    Detail      = weak.Count == 0
                        ? "Yhdistetyn AP:n signaali riittävä."
                        : $"Heikko signaali ({weak.First().Rssi} dBm) yhdistetyssä AP:ssa '{weak.First().Ssid}'."
                });
            }

            // ── ISO 27001 A.8.20-4 — EAPOL / PMKID-keräily ──────────
            {
                var suspicious = eapolSummary.Where(e => e.Suspicious).ToList();
                ComplianceStatus st = suspicious.Count == 0
                    ? ComplianceStatus.Pass : ComplianceStatus.Warning;
                report.Rules.Add(new ComplianceRule
                {
                    Id = "ISO-A.8.20-4", Standard = "ISO 27001:2022",
                    Requirement = "A.8.20 — Verkkoturvallisuuden seuranta",
                    Description = "PMKID-keräilyhyökkäykset tunnistetaan kun laite kättelee yli 3 AP:ta 60 sekunnissa.",
                    Status      = st,
                    Detail      = suspicious.Count == 0
                        ? "Ei epäilyttävää EAPOL-aktiivisuutta."
                        : $"{suspicious.Count} laitetta epäilyttävässä EAPOL-toiminnassa: " +
                          string.Join(", ", suspicious.Select(e => $"{e.ClientMac} ({e.DistinctAps} AP:ta)"))
                });
            }

            // ── Kokonaispisteytys ─────────────────────────────────────
            report.PassCount = report.Rules.Count(r => r.Status == ComplianceStatus.Pass);
            report.FailCount = report.Rules.Count(r => r.Status == ComplianceStatus.Fail);
            report.WarnCount = report.Rules.Count(r => r.Status == ComplianceStatus.Warning);
            int infoCount    = report.Rules.Count(r => r.Status == ComplianceStatus.Info);

            // Pisteet: Pass=10, Info=8, Warning=5, Fail=0
            int maxScore = report.Rules.Count * 10;
            int rawScore = report.PassCount * 10 + infoCount * 8 + report.WarnCount * 5;
            report.Score = maxScore > 0 ? (int)((double)rawScore / maxScore * 100) : 0;

            report.OverallGrade = report.Score >= 90 ? "A"
                : report.Score >= 80 ? "B"
                : report.Score >= 70 ? "C"
                : report.Score >= 60 ? "D"
                : "F";

            return report;
        }
    }
}
