using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace WifiAnalyzerPro
{
    public class WifiConfig
    {
        // ── Skannaus ──────────────────────────────────────────────
        public int  MinScanIntervalSeconds       { get; set; } = 12;
        public int  BssStaleThresholdSeconds     { get; set; } = 25;
        public int  ScanTimeoutSeconds           { get; set; } = 6;
        public int  StaleApMinutes               { get; set; } = 5;
        public int  MinApCountBeforeForceScan    { get; set; } = 2;
        public int  ScanRetryAfterFailureSeconds { get; set; } = 5;

        // ── Konsoli ───────────────────────────────────────────────
        public int  MaxConsoleRows               { get; set; } = 15;
        public int  FullRefreshMs                { get; set; } = 4000;
        /// <summary>"green" | "cyan" | "white" — konsolinäkymän teemaväri</summary>
        public string ThemeColor                 { get; set; } = "green";

        // ── Tallennus ─────────────────────────────────────────────
        public string SaveDirectory              { get; set; } = ".";
        public int    SaveIntervalSeconds        { get; set; } = 10;
        public int    JsonRetentionHours         { get; set; } = 24;
        public int    MaxHistoryPoints           { get; set; } = 120;

        // ── Hälytykset ────────────────────────────────────────────
        public int    RssiAlertThreshold         { get; set; } = -80;
        public bool   AlertOnNewAp               { get; set; } = true;
        public string AlertLogPath               { get; set; } = "alerts.log";
        public List<string> SuppressedAlertTypes { get; set; } = new List<string>();
        public int    AlertCooldownSeconds       { get; set; } = 60;
        /// <summary>Hystereesin nollauspiste — oltava suurempi kuin RssiAlertThreshold.</summary>
        public int    RssiAlertClearThreshold    { get; set; } = -75;
        /// <summary>Webhook-URL johon lähetetään POST JSON-hälytyksiä. Tyhjä = pois käytöstä.</summary>
        public string AlertWebhookUrl            { get; set; } = "";

        // ── Pisteytys ─────────────────────────────────────────────
        public double CoChannelPenaltyWeight     { get; set; } = 6.0;
        public double AdjacentPenaltyWeight      { get; set; } = 3.0;

        // ── Pitkäaikaisdata ───────────────────────────────────────
        public bool   EnableLongTermExport       { get; set; } = true;

        // ── Nopeusmittaus ─────────────────────────────────────────
        public string SpeedTestUrl               { get; set; } = "http://speedtest.tele2.net/1MB.zip";
        public int    SpeedTestIntervalMinutes   { get; set; } = 5;

        // ── Web-dashboard ─────────────────────────────────────────
        /// <summary>HTTP-portti paikalliselle dashboardille. 0 = pois käytöstä.</summary>
        public int    WebDashboardPort           { get; set; } = 8765;

        // ── Prometheus ────────────────────────────────────────────
        public bool   EnablePrometheusExport     { get; set; } = false;

        // ── Wi-Fi 6E / 7 ─────────────────────────────────────────
        public bool   Enable6GhzSupport          { get; set; } = true;
        /// <summary>Älä hälyytä Evil Twiniä MAC-randomisaatiota käyttävistä laitteista.</summary>
        public bool   MacRandomizationFilter     { get; set; } = true;

        // ── Ulkoiset hälytykset (Discord / Slack / Generic) ─────────
        /// <summary>Discord webhook URL. Tyhjä = pois käytöstä.</summary>
        public string DiscordWebhookUrl               { get; set; } = "";
        /// <summary>Slack Incoming Webhook URL. Tyhjä = pois käytöstä.</summary>
        public string SlackWebhookUrl                 { get; set; } = "";
        /// <summary>Blacklist-vakavuustaso josta ulkoinen hälytys lähetetään (1–3).</summary>
        public int    BlacklistAlertSeverityThreshold { get; set; } = 3;
        /// <summary>Cooldown-aika ennen saman domainin uutta ulkoista hälytystä (minuuttia).</summary>
        public int    SecurityAlertCooldownMinutes    { get; set; } = 5;

        // ── Automaattinen PCAP-nauhoitus (Forensiikka) ──────────────
        /// <summary>Käynnistääkö vakava turvapoikkeama (Evil Twin/Blacklist 3) automaattisen PCAP-nauhoituksen.</summary>
        public bool   EnableAutoCapture               { get; set; } = false;
        /// <summary>Hakemisto johon PCAP-tiedostot tallennetaan.</summary>
        public string CaptureDirectory                { get; set; } = ".";
        /// <summary>Nauhoituksen kesto sekunteina.</summary>
        public int    CaptureDurationSeconds          { get; set; } = 60;
        /// <summary>PCAP-tiedoston maksimikoko tavuina (oletus 50 Mt).</summary>
        public long   CaptureMaxFileSizeBytes         { get; set; } = 52_428_800;
        /// <summary>Samanaikaisten PCAP-nauhoitusten enimmäismäärä.</summary>
        public int    MaxConcurrentCaptures           { get; set; } = 3;

        // ── Honeypot ──────────────────────────────────────────────
        /// <summary>Decoy-SSID:t joihin yhdistämistä seurataan. Tyhjä = käytetään oletuksia.</summary>
        public List<string> HoneypotSsids             { get; set; } = new List<string>();
        /// <summary>Käynnistääkö ohjelman käynnistys aktiivisen SoftAP-haamutukiaseman.</summary>
        public bool   EnableHoneypotSoftAp            { get; set; } = false;
        /// <summary>Aktiivisen SoftAP:n SSID. Tyhjä = käytetään ensimmäistä HoneypotSsids-listalta.</summary>
        public string HoneypotSoftApSsid              { get; set; } = "";

        // ── Reitittimen automaattinen MAC-esto ───────────────────
        // Unifi Network Application
        public string UnifiControllerUrl  { get; set; } = "";
        public string UnifiUsername       { get; set; } = "";
        public string UnifiPassword       { get; set; } = "";
        public string UnifiSite           { get; set; } = "default";
        // pfSense REST API
        public string PfSenseUrl          { get; set; } = "";
        public string PfSenseApiKey       { get; set; } = "";
        public string PfSenseUsername     { get; set; } = "admin";
        public string PfSensePassword     { get; set; } = "";
        public string PfSenseMacAlias     { get; set; } = "wifi_blacklist";
        // OPNsense REST API
        public string OPNsenseUrl         { get; set; } = "";
        public string OPNsenseKey         { get; set; } = "";
        public string OPNsenseSecret      { get; set; } = "";
        public string OPNsenseMacAlias    { get; set; } = "wifi_blacklist";

        // ── Ulkoinen uhkatiedustelu (Threat Intelligence) ────────
        /// <summary>AlienVault OTX API-avain. Tyhjä = pois käytöstä.</summary>
        public string OtxApiKey                    { get; set; } = "";
        /// <summary>AbuseIPDB API-avain. Tyhjä = pois käytöstä.</summary>
        public string AbuseIpDbApiKey              { get; set; } = "";
        /// <summary>Uhkatiedustelun muisticachen TTL tunteina.</summary>
        public int    ThreatIntelCacheTtlHours     { get; set; } = 24;
        /// <summary>Maksimi API-kutsua tunnissa (free tier -rajoitukset).</summary>
        public int    ThreatIntelMaxRequestsPerHour { get; set; } = 100;
        /// <summary>Käynnistää uhkatiedustelun. Vaatii vähintään yhden API-avaimen.</summary>
        public bool   EnableThreatIntel            { get; set; } = false;

        // ── Sähköpostihälytykset (SMTP) ──────────────────────────
        /// <summary>SMTP-palvelimen osoite. Tyhjä = pois käytöstä.</summary>
        public string SmtpHost                     { get; set; } = "";
        /// <summary>SMTP-portti (587 = STARTTLS, 465 = SSL, 25 = plain).</summary>
        public int    SmtpPort                     { get; set; } = 587;
        /// <summary>SMTP-käyttäjätunnus (tyypillisesti sähköpostiosoite).</summary>
        public string SmtpUser                     { get; set; } = "";
        /// <summary>SMTP-salasana tai sovellussalasana.</summary>
        public string SmtpPassword                 { get; set; } = "";
        /// <summary>Lähettäjän sähköpostiosoite.</summary>
        public string SmtpFrom                     { get; set; } = "wifianalyzer@localhost";
        /// <summary>Vastaanottajan sähköpostiosoite. Pilkulla erotettu lista.</summary>
        public string SmtpTo                       { get; set; } = "";
        /// <summary>Minimivakavuus sähköpostihälytykseen (1–3).</summary>
        public int    SmtpAlertSeverityThreshold   { get; set; } = 3;
        /// <summary>Käytä SSL/TLS-yhteyttä.</summary>
        public bool   SmtpUseSsl                   { get; set; } = true;

        // ── PCAP-hakemiston hallinta ──────────────────────────────
        /// <summary>Hakemiston maksimikoko megatavuina ennen vanhojen tiedostojen poistoa. 0 = ei rajaa.</summary>
        public int    CaptureMaxDirectorySizeMb     { get; set; } = 500;
        /// <summary>Vanhentuneiden PCAP-tiedostojen säilytysaika päivinä. 0 = ei ikärajaa.</summary>
        public int    CaptureRetentionDays          { get; set; } = 30;

        // ── Automaattinen compliance-raportti ────────────────────
        /// <summary>Viikonpäivä automaattiselle compliance-raportille (0=Sun, 1=Mon...). -1 = pois käytöstä.</summary>
        public int    ComplianceScheduleDay         { get; set; } = -1;
        /// <summary>Tunti (0–23) jolloin automaattinen compliance-raportti generoidaan.</summary>
        public int    ComplianceScheduleHour        { get; set; } = 8;

        // ── Kanavasuositus ────────────────────────────────────────
        /// <summary>Häiriöpisteraja jonka ylittyessä kanavasuositus lähetetään.</summary>
        public double ChannelRecommendationThreshold { get; set; } = 15.0;
        /// <summary>Lähetä kanavasuositus myös webhookilla.</summary>
        public bool   ChannelRecommendationWebhook  { get; set; } = true;

        // ── Captive portal -tunnistus ─────────────────────────────
        /// <summary>Tunnista captive portal -verkot (DNS-kaappaus). true = aktiivinen.</summary>
        public bool   DetectCaptivePortal           { get; set; } = true;
        /// <summary>Kuinka monta % DNS-kyselyistä samaan IP:hen ennen tunnistusta.</summary>
        public int    CaptivePortalDnsThresholdPct  { get; set; } = 80;
    }

    public enum ScanOutcome { None, Running, Ok, Cancelled, Error }

    public static class WifiConfigLoader
    {
        private const string DefaultPath = "wifi_config.json";

        private static readonly JsonSerializerOptions JsonRead  =
            new() { PropertyNameCaseInsensitive = true };
        private static readonly JsonSerializerOptions JsonWrite =
            new() { WriteIndented = true };

        public static WifiConfig Load(string path = DefaultPath)
        {
            if (!File.Exists(path)) { var d = new WifiConfig(); Save(d, path); return d; }
            try
            {
                var cfg = JsonSerializer.Deserialize<WifiConfig>(
                    File.ReadAllText(path, System.Text.Encoding.UTF8), JsonRead);
                return cfg ?? new WifiConfig();
            }
            catch (Exception ex) { AppLogger.Log($"[Config] Lataus: {ex.Message}"); return new WifiConfig(); }
        }

        public static void Save(WifiConfig cfg, string path = DefaultPath)
        {
            try { File.WriteAllText(path, JsonSerializer.Serialize(cfg, JsonWrite), System.Text.Encoding.UTF8); }
            catch (Exception ex) { AppLogger.Log($"[Config] Tallennus: {ex.Message}"); }
        }

        public static List<string> Validate(WifiConfig cfg)
        {
            var w = new List<string>();
            if (cfg.MinScanIntervalSeconds < 5)
                w.Add($"⚠ MinScanIntervalSeconds ({cfg.MinScanIntervalSeconds}) alle 5 s — voi kuormittaa WiFi-adapteria.");
            if (cfg.SaveIntervalSeconds < 5)
                w.Add($"⚠ SaveIntervalSeconds ({cfg.SaveIntervalSeconds}) alle 5 s — paljon levykirjoituksia.");
            if (cfg.JsonRetentionHours < 1)
                w.Add($"⚠ JsonRetentionHours ({cfg.JsonRetentionHours}) alle 1 — raportit poistetaan heti.");
            if (cfg.RssiAlertThreshold > -50)
                w.Add($"⚠ RssiAlertThreshold ({cfg.RssiAlertThreshold} dBm) yli -50 — hälyttää lähes jatkuvasti.");
            if (cfg.RssiAlertClearThreshold <= cfg.RssiAlertThreshold)
                w.Add($"⚠ RssiAlertClearThreshold ({cfg.RssiAlertClearThreshold}) pitää olla suurempi kuin " +
                      $"RssiAlertThreshold ({cfg.RssiAlertThreshold}) jotta hystereesi toimii.");
            if (cfg.AlertCooldownSeconds < 0)
                w.Add($"⚠ AlertCooldownSeconds ({cfg.AlertCooldownSeconds}) negatiivinen.");
            if (!string.IsNullOrWhiteSpace(cfg.SaveDirectory) && cfg.SaveDirectory != "." &&
                !Directory.Exists(cfg.SaveDirectory))
                w.Add($"⚠ SaveDirectory '{cfg.SaveDirectory}' ei ole olemassa — luodaan automaattisesti.");
            if (cfg.MaxConsoleRows < 5 || cfg.MaxConsoleRows > 50)
                w.Add($"⚠ MaxConsoleRows ({cfg.MaxConsoleRows}) epätavallinen arvo (suositus 10–30).");
            if (cfg.ScanTimeoutSeconds < 3)
                w.Add($"⚠ ScanTimeoutSeconds ({cfg.ScanTimeoutSeconds}) alle 3 s.");
            if (!Uri.TryCreate(cfg.SpeedTestUrl, UriKind.Absolute, out _))
                w.Add($"⚠ SpeedTestUrl '{cfg.SpeedTestUrl}' ei ole kelvollinen URL.");
            if (cfg.MaxHistoryPoints < 20 || cfg.MaxHistoryPoints > 1000)
                w.Add($"⚠ MaxHistoryPoints ({cfg.MaxHistoryPoints}) suositus 60–360.");
            if (!string.IsNullOrWhiteSpace(cfg.AlertWebhookUrl) &&
                !Uri.TryCreate(cfg.AlertWebhookUrl, UriKind.Absolute, out _))
                w.Add($"⚠ AlertWebhookUrl '{cfg.AlertWebhookUrl}' ei ole kelvollinen URL.");
            return w;
        }
    }
}
