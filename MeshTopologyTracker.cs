using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace WifiAnalyzerPro
{
    // ── Datatyypit ────────────────────────────────────────────────

    /// <summary>Yksittäinen roaming-tapahtuma saman SSID:n AP:iden välillä.</summary>
    public class RoamingEvent
    {
        public DateTime Time        { get; set; } = DateTime.Now;
        public string   Ssid        { get; set; }
        public string   FromBssid   { get; set; }
        public string   ToBssid     { get; set; }
        public int      FromRssi    { get; set; }
        public int      ToRssi      { get; set; }
        public string   FromVendor  { get; set; }
        public string   ToVendor    { get; set; }
        public double   DeltaMs     { get; set; } // roaming-viive ms
    }

    /// <summary>Yksi mesh-ryhmä: saman SSID:n AP:t ja niiden väliset linkit.</summary>
    public class MeshGroup
    {
        public string         Ssid       { get; set; }
        public List<MeshNode> Nodes      { get; set; } = new();
        public List<MeshLink> Links      { get; set; } = new();
        public bool           IsMesh     { get; set; } // ≥2 AP:ta samalla SSID:llä
        public DateTime       UpdatedAt  { get; set; } = DateTime.Now;
    }

    public class MeshNode
    {
        public string Bssid   { get; set; }
        public string Vendor  { get; set; }
        public int    Rssi    { get; set; }
        public int    Channel { get; set; }
        public string Band    { get; set; }
        public bool   IsConnected { get; set; }
        public int    RoamCount  { get; set; } // kuinka monta kertaa tähän roamattu
    }

    public class MeshLink
    {
        public string FromBssid { get; set; }
        public string ToBssid   { get; set; }
        public int    Count     { get; set; } // roaming-kerrat tällä välillä
        public DateTime LastAt  { get; set; }
    }

    /// <summary>
    /// Seuraa mesh-verkkojen topologiaa ja roaming-tapahtumia.
    ///
    /// Mesh-ryhmä = joukko AP:ita joilla on sama SSID (ESS).
    /// Roaming-tapahtuma = ConnectedBssidSafe vaihtuu toisen SSID:llä olevan
    /// AP:n BSSID:ksi.
    ///
    /// Topologia piirretään dashboardiin SVG-kaaviona:
    ///   ○ AP-solmu: ympyrä BSSID + RSSI
    ///   — Linkki:  nuoli roaming-suuntaan, paksuus = roaming-kerrat
    /// </summary>
    public sealed class MeshTopologyTracker
    {
        // SSID → ryhmä
        private readonly ConcurrentDictionary<string, MeshGroup> _groups =
            new(StringComparer.OrdinalIgnoreCase);

        // Roaming-historia (ring-jono max 200)
        private readonly ConcurrentQueue<RoamingEvent> _history = new();
        private const int MaxHistory = 200;

        // Edellinen yhdistys — tunnistaa roaming-tapahtuman
        private string _lastConnectedBssid = null;
        private string _lastConnectedSsid  = null;
        private DateTime _lastConnectedAt  = DateTime.MinValue;

        // ── Päivitys ──────────────────────────────────────────────

        /// <summary>
        /// Kutsutaan joka skannausiteraatiossa AP-listan ja yhdistetyn BSSID:n kanssa.
        /// </summary>
        public void Update(
            List<AnalyzedAccessPoint> aps,
            string connectedBssid,
            OuiDatabase oui)
        {
            if (aps == null) return;

            // 1. Rakenna/päivitä mesh-ryhmät SSID:n mukaan
            var bySsid = aps
                .Where(a => !string.IsNullOrWhiteSpace(a.Ssid) && a.Ssid != "<piilotettu>")
                .GroupBy(a => a.Ssid, StringComparer.OrdinalIgnoreCase);

            foreach (var grp in bySsid)
            {
                var apList = grp.ToList();
                var group  = _groups.GetOrAdd(grp.Key, k => new MeshGroup { Ssid = k });

                group.IsMesh    = apList.Count >= 2;
                group.UpdatedAt = DateTime.Now;

                // KORJAUS 4: lasketaan roaming-kerrat etukäteen Dictionary:iin
                // Aiemmin CountRoamsTo() skannasi koko _history-jonon jokaiselle AP:lle
                // → O(n × |history|) per iteraatio. Nyt O(|history|) kerran per päivitys.
                var roamCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                foreach (var ev in _history)
                {
                    if (ev.ToBssid == null) continue;
                    roamCounts.TryGetValue(ev.ToBssid, out int c);
                    roamCounts[ev.ToBssid] = c + 1;
                }

                group.Nodes = apList.Select(a => new MeshNode
                {
                    Bssid       = a.Bssid,
                    Vendor      = a.Vendor ?? oui?.Lookup(a.Bssid) ?? "",
                    Rssi        = a.Rssi,
                    Channel     = a.Channel,
                    Band        = a.Band ?? "",
                    IsConnected = string.Equals(a.Bssid, connectedBssid,
                                      StringComparison.OrdinalIgnoreCase),
                    RoamCount   = roamCounts.TryGetValue(a.Bssid, out int rc) ? rc : 0,
                }).ToList();
            }

            // Poista ryhmät joita ei enää näy (>5 min)
            var stale = _groups.Where(g => (DateTime.Now - g.Value.UpdatedAt).TotalMinutes > 5)
                                .Select(g => g.Key).ToList();
            foreach (var k in stale) _groups.TryRemove(k, out _);

            // 2. Tunnista roaming-tapahtuma
            if (!string.IsNullOrEmpty(connectedBssid) &&
                connectedBssid != _lastConnectedBssid)
            {
                // Etsi SSID yhdistetystä AP:sta
                var connAp = aps.FirstOrDefault(a =>
                    string.Equals(a.Bssid, connectedBssid, StringComparison.OrdinalIgnoreCase));

                if (connAp != null && _lastConnectedBssid != null)
                {
                    // Roaming vain jos sama SSID
                    if (string.Equals(connAp.Ssid, _lastConnectedSsid,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        var prevAp = aps.FirstOrDefault(a =>
                            string.Equals(a.Bssid, _lastConnectedBssid,
                                StringComparison.OrdinalIgnoreCase));

                        var roam = new RoamingEvent
                        {
                            Ssid       = connAp.Ssid,
                            FromBssid  = _lastConnectedBssid,
                            ToBssid    = connectedBssid,
                            FromRssi   = prevAp?.Rssi ?? 0,
                            ToRssi     = connAp.Rssi,
                            FromVendor = prevAp?.Vendor ?? oui?.Lookup(_lastConnectedBssid) ?? "",
                            ToVendor   = connAp.Vendor ?? oui?.Lookup(connectedBssid) ?? "",
                            DeltaMs    = (DateTime.Now - _lastConnectedAt).TotalMilliseconds,
                        };
                        RecordRoaming(roam);
                        UpdateLink(roam);

                        AppLogger.Log($"[Mesh] Roaming: '{connAp.Ssid}' " +
                            $"{_lastConnectedBssid} ({roam.FromRssi} dBm) → " +
                            $"{connectedBssid} ({roam.ToRssi} dBm) " +
                            $"Δ{roam.DeltaMs:F0} ms");
                    }
                }

                _lastConnectedBssid = connectedBssid;
                _lastConnectedSsid  = connAp?.Ssid;
                _lastConnectedAt    = DateTime.Now;
            }
        }

        private void RecordRoaming(RoamingEvent ev)
        {
            _history.Enqueue(ev);
            while (_history.Count > MaxHistory) _history.TryDequeue(out _);
        }

        private void UpdateLink(RoamingEvent ev)
        {
            if (!_groups.TryGetValue(ev.Ssid, out var grp)) return;
            var link = grp.Links.FirstOrDefault(l =>
                l.FromBssid == ev.FromBssid && l.ToBssid == ev.ToBssid);
            if (link == null)
            {
                link = new MeshLink { FromBssid = ev.FromBssid, ToBssid = ev.ToBssid };
                grp.Links.Add(link);
            }
            link.Count++;
            link.LastAt = DateTime.Now;
        }

        // ── Julkinen lukurajapinta ─────────────────────────────────

        public List<MeshGroup> GetGroups()
            => _groups.Values.OrderByDescending(g => g.Nodes.Count).ToList();

        public List<MeshGroup> GetMeshGroups()
            => _groups.Values.Where(g => g.IsMesh)
                             .OrderByDescending(g => g.Nodes.Count).ToList();

        public List<RoamingEvent> GetRecentRoaming(int max = 30)
        {
            var arr = _history.ToArray();
            return arr.Skip(Math.Max(0, arr.Length - max)).Reverse().ToList();
        }

        public int TotalRoamingEvents => _history.Count;

        // ── SVG-topologiakaavio ───────────────────────────────────

        /// <summary>
        /// Generoi SVG-merkkijonon mesh-ryhmän topologiakaavioksi.
        /// AP:t ympyröinä, roaming-tapahtumat nuolina.
        /// Kutsutaan dashboardin JavaScript-päivityksestä.
        /// </summary>
        public string BuildSvg(MeshGroup grp, int width = 400, int height = 220)
        {
            if (grp == null || grp.Nodes.Count == 0) return "";

            var sb = new System.Text.StringBuilder();
            sb.Append($"<svg viewBox='0 0 {width} {height}' xmlns='http://www.w3.org/2000/svg' " +
                      $"style='background:transparent;font-family:monospace'>");

            int n = grp.Nodes.Count;
            // Sijoita solmut ympyrän kehälle
            double cx = width / 2.0, cy = height / 2.0;
            double r  = Math.Min(cx, cy) * 0.65;

            var positions = new (double x, double y)[n];
            for (int i = 0; i < n; i++)
            {
                double angle = (2 * Math.PI * i / n) - Math.PI / 2;
                positions[i] = (cx + r * Math.Cos(angle), cy + r * Math.Sin(angle));
            }

            // Piirrä linkit (roaming-nuolet)
            foreach (var link in grp.Links)
            {
                int fi = grp.Nodes.FindIndex(nd => nd.Bssid == link.FromBssid);
                int ti = grp.Nodes.FindIndex(nd => nd.Bssid == link.ToBssid);
                if (fi < 0 || ti < 0) continue;

                var (fx, fy) = positions[fi];
                var (tx, ty) = positions[ti];
                int sw = Math.Max(1, Math.Min(5, link.Count));
                sb.Append($"<line x1='{fx:F0}' y1='{fy:F0}' x2='{tx:F0}' y2='{ty:F0}' " +
                          $"stroke='#3b82f6' stroke-width='{sw}' stroke-opacity='0.6' " +
                          $"marker-end='url(#arr)'/>");
            }

            // Piirrä solmut
            for (int i = 0; i < n; i++)
            {
                var nd = grp.Nodes[i];
                var (px, py) = positions[i];
                string fill  = nd.IsConnected ? "#10b981" :
                               nd.Rssi >= -60 ? "#3b82f6" :
                               nd.Rssi >= -75 ? "#f59e0b" : "#ef4444";
                string bssidShort = nd.Bssid?.Length >= 8
                    ? nd.Bssid.Substring(nd.Bssid.Length - 8) : nd.Bssid ?? "?";

                sb.Append($"<circle cx='{px:F0}' cy='{py:F0}' r='22' fill='{fill}' " +
                          $"fill-opacity='0.85' stroke='#1e293b' stroke-width='2'/>");
                sb.Append($"<text x='{px:F0}' y='{py - 4:F0}' text-anchor='middle' " +
                          $"fill='#f1f5f9' font-size='9'>{HE(bssidShort)}</text>");
                sb.Append($"<text x='{px:F0}' y='{py + 8:F0}' text-anchor='middle' " +
                          $"fill='#f1f5f9' font-size='9'>{nd.Rssi} dBm</text>");
                if (nd.RoamCount > 0)
                    sb.Append($"<text x='{px:F0}' y='{py + 20:F0}' text-anchor='middle' " +
                              $"fill='#fbbf24' font-size='8'>↷{nd.RoamCount}</text>");
            }

            // Nuolenpää-marker
            sb.Append("<defs><marker id='arr' markerWidth='8' markerHeight='8' " +
                      "refX='6' refY='3' orient='auto'>" +
                      "<path d='M0,0 L0,6 L8,3 z' fill='#3b82f6' opacity='0.8'/>" +
                      "</marker></defs>");

            // Otsikko
            sb.Append($"<text x='{width / 2}' y='16' text-anchor='middle' " +
                      $"fill='#94a3b8' font-size='11'>{HE(grp.Ssid)} — {n} AP</text>");

            sb.Append("</svg>");
            return sb.ToString();
        }

        private static string HE(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
        }
    }
}
