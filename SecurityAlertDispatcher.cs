using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Lähettää kriittiset tietoturvahälytykset ulkoisiin kanaviin.
    ///
    /// Tuetut kanavat:
    ///   • Discord   — Incoming Webhook, rich embed värikoodauksella
    ///   • Slack     — Incoming Webhook, Block Kit -viesti
    ///   • Generic   — HTTP POST JSON (sama formaatti kuin AlertManager)
    ///
    /// Cooldown: sama (domain, tyyppi) -avain hälyttää enintään kerran
    /// SecurityAlertCooldownMinutes aikavälillä — ei spam-tulvaa.
    ///
    /// Käyttö:
    ///   var dispatcher = new SecurityAlertDispatcher(cfg);
    ///   dispatcher.SendAsync("Blacklist", "xmrig.com", "XMRig miner", 3);
    /// </summary>
    public sealed class SecurityAlertDispatcher : IDisposable
    {
        private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

        private string _discordUrl;
        private string _slackUrl;
        private string _genericUrl;
        private int    _severityThreshold;
        private int    _cooldownMinutes;

        // Cooldown: avain = "tyyppi:domain" → viimeisin lähetysaika
        private readonly ConcurrentDictionary<string, DateTime> _lastSent =
            new(StringComparer.OrdinalIgnoreCase);

        public SecurityAlertDispatcher(WifiConfig cfg) => Apply(cfg);

        public void Apply(WifiConfig cfg)
        {
            _discordUrl         = cfg.DiscordWebhookUrl  ?? "";
            _slackUrl           = cfg.SlackWebhookUrl    ?? "";
            _genericUrl         = cfg.AlertWebhookUrl    ?? "";
            _severityThreshold  = cfg.BlacklistAlertSeverityThreshold;
            _cooldownMinutes    = cfg.SecurityAlertCooldownMinutes;
        }

        /// <summary>
        /// Lähettää hälytyksen konfiguroituihin kanaviin asynkronisesti.
        /// </summary>
        /// <param name="alertType">"Blacklist", "EvilTwin", "DeauthStorm" jne.</param>
        /// <param name="subject">Domain, BSSID tai muu tunniste.</param>
        /// <param name="detail">Yksityiskohtainen selitys.</param>
        /// <param name="severity">1–3 (1=seuranta, 2=epäilyttävä, 3=kriittinen)</param>
        public void SendAsync(string alertType, string subject, string detail, int severity)
        {
            if (severity < _severityThreshold) return;
            if (!ShouldSend(alertType, subject))  return;

            // Käynnistä fire-and-forget — ei blokaa moottoria
            Task.Run(async () =>
            {
                await DispatchAllAsync(alertType, subject, detail, severity);
            });
        }

        private bool ShouldSend(string type, string subject)
        {
            string key = $"{type}:{subject}";
            if (_lastSent.TryGetValue(key, out var last) &&
                (DateTime.Now - last).TotalMinutes < _cooldownMinutes)
                return false;
            _lastSent[key] = DateTime.Now;
            return true;
        }

        private async Task DispatchAllAsync(string type, string subject, string detail, int severity)
        {
            string ts    = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string emoji = severity >= 3 ? "🚨" : severity >= 2 ? "⚠️" : "ℹ️";
            string sev   = severity >= 3 ? "KRIITTINEN" : severity >= 2 ? "Epäilyttävä" : "Seuranta";

            var tasks = new List<Task>();

            if (!string.IsNullOrWhiteSpace(_discordUrl))
                tasks.Add(SendDiscordAsync(_discordUrl, type, subject, detail, sev, emoji, ts, severity));

            if (!string.IsNullOrWhiteSpace(_slackUrl))
                tasks.Add(SendSlackAsync(_slackUrl, type, subject, detail, sev, emoji, ts, severity));

            if (!string.IsNullOrWhiteSpace(_genericUrl))
                tasks.Add(SendGenericAsync(_genericUrl, type, subject, detail, severity, ts));

            foreach (var t in tasks)
                try { await t.ConfigureAwait(false); }
                catch (Exception ex) { AppLogger.Log($"[Dispatch] {ex.Message}"); }
        }

        // ── Discord ───────────────────────────────────────────────

        private static async Task SendDiscordAsync(
            string url, string type, string subject, string detail,
            string sev, string emoji, string ts, int severity)
        {
            // Discord embed väri: punainen=kriittinen, oranssi=epäilyttävä, keltainen=seuranta
            int color = severity >= 3 ? 0xE53E3E : severity >= 2 ? 0xED8936 : 0xECC94B;

            var payload = new
            {
                username = "WifiAnalyzerPro",
                embeds = new[]
                {
                    new
                    {
                        title       = $"{emoji} {sev}: {type}",
                        description = $"**Kohde:** `{subject}`\n**Selitys:** {detail}",
                        color,
                        fields = new[]
                        {
                            new { name = "Vakavuus", value = $"{severity}/3", inline = true },
                            new { name = "Aika",     value = ts,             inline = true },
                        },
                        footer = new { text = "WifiAnalyzerPro · Automaattinen hälytys" }
                    }
                }
            };

            string json = JsonSerializer.Serialize(payload);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync(url, content).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                AppLogger.Log($"[Discord] HTTP {(int)resp.StatusCode}");
            else
                AppLogger.Log($"[Discord] Hälytys lähetetty: {type} / {subject}");
        }

        // ── Slack ──────────────────────────────────────────────────

        private static async Task SendSlackAsync(
            string url, string type, string subject, string detail,
            string sev, string emoji, string ts, int severity)
        {
            string color = severity >= 3 ? "#E53E3E" : severity >= 2 ? "#ED8936" : "#ECC94B";

            // Block Kit -formaatti
            var payload = new
            {
                attachments = new[]
                {
                    new
                    {
                        color,
                        blocks = new object[]
                        {
                            new
                            {
                                type = "section",
                                text = new
                                {
                                    type = "mrkdwn",
                                    text = $"{emoji} *{sev}: {type}*\n*Kohde:* `{subject}`\n*Selitys:* {detail}"
                                }
                            },
                            new
                            {
                                type = "context",
                                elements = new[]
                                {
                                    new { type = "mrkdwn", text = $"Vakavuus: *{severity}/3* · {ts} · WifiAnalyzerPro" }
                                }
                            }
                        }
                    }
                }
            };

            string json = JsonSerializer.Serialize(payload);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync(url, content).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                AppLogger.Log($"[Slack] HTTP {(int)resp.StatusCode}");
            else
                AppLogger.Log($"[Slack] Hälytys lähetetty: {type} / {subject}");
        }

        // ── Generic HTTP webhook ───────────────────────────────────

        private static async Task SendGenericAsync(
            string url, string type, string subject,
            string detail, int severity, string ts)
        {
            var payload = new
            {
                ts,
                type,
                subject,
                detail,
                severity,
                source = "WifiAnalyzerPro"
            };
            string json = JsonSerializer.Serialize(payload);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync(url, content).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                AppLogger.Log($"[Webhook] HTTP {(int)resp.StatusCode}");
        }

        public void Dispose() { }
    }
}
