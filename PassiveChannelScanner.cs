using System;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace WifiAnalyzerPro
{
    // ═══════════════════════════════════════════════════════════
    // PASSIIVINEN KANAVASKANNAUS
    //
    // KORJAUKSET tähän versioon:
    //   • Dictionary<string,PassiveBeaconInfo>:n käyttö Listin sijaan → O(1) per pkt.
    //   • BSS Load Element (IE 11) -parserointi → todellinen kanavakuorma.
    //   • Frekvenssin (MHz) talteenotto radiotapin Channel-kentästä → 6 GHz erottuu.
    //   • TSFT-kentän 8-tavun tasaus dokumentoitu (oli aiemmin clampattu 4:ään).
    // ═══════════════════════════════════════════════════════════

    public class PassiveChannelScanner : IDisposable
    {
        private volatile string _status = "Odottaa paketteja...";

        private readonly ConcurrentDictionary<string, PassiveBeaconInfo> _beacons =
            new(StringComparer.OrdinalIgnoreCase);

        public string Status => _status;
        public event Action<PassiveBeaconInfo> BeaconReceived;

        /// <summary>Deauth/Disassoc-kehys havaittu — DeauthTracker kutsuu Record().</summary>
        public event Action<DeauthEvent> DeauthReceived;

        /// <summary>RTS-kehys havaittu kanavalla N.</summary>
        public event Action<int> RtsReceived;
        /// <summary>CTS-kehys havaittu kanavalla N.</summary>
        public event Action<int> CtsReceived;

        /// <summary>
        /// DNS-hostname havaittu avoimesta Data-kehyksestä.
        /// Parametrit: (hostname, sourceMac, bssid)
        /// </summary>
        public event Action<string, string, string> DnsQueryDetected;

        /// <summary>
        /// TLS SNI havaittu avoimesta Data-kehyksestä.
        /// Parametrit: (sni, sourceMac, bssid)
        /// </summary>
        public event Action<string, string, string> TlsSniDetected;

        /// <summary>
        /// Probe Request (subtype 4) havaittu.
        /// Parametrit: (sourceMac, probedSsid, rawData, macFrameOffset)
        /// WifiHoneypot tarkistaa kohdistuuko probe decoy-SSID:hen.
        /// </summary>
        public event Action<string, string, byte[], int> ProbeRequestDetected;

        // Avoimet BSSID:t DNS/TLS-analyysiin (päivitetään BeaconReceived:stä)
        private readonly ConcurrentDictionary<string, bool> _openNetworkBssids =
            new(StringComparer.OrdinalIgnoreCase);

        // Moottori kutsuu tätä jokaiselle kaapatulle paketille
        public void ProcessPacket(byte[] data, DateTime ts)
        {
            try
            {
                // ── Radiotap-otsikko ─────────────────────────────────
                if (data == null || data.Length < 4) return;
                int rtLen = data[2] | (data[3] << 8);
                if (rtLen < 8 || rtLen >= data.Length) return;

                int off = rtLen;
                if (off + 2 >= data.Length) return;

                byte fc0 = data[off];
                byte fc1 = data[off + 1];

                int frameType    = (fc0 >> 2) & 0x3;
                int frameSubtype = (fc0 >> 4) & 0xF;

                switch (frameType)
                {
                    case 0: // Management
                        HandleManagementFrame(data, ts, off, frameSubtype, rtLen);
                        break;
                    case 1: // Control
                        HandleControlFrame(data, off, frameSubtype);
                        break;
                    case 2: // Data
                        HandleDataFrame(data, off, frameSubtype, fc1);
                        break;
                }
            }
            catch (Exception ex) { AppLogger.Log($"[Passive] ProcessPacket: {ex.Message}"); }
        }

        // ── Management-kehykset ───────────────────────────────────────

        private void HandleManagementFrame(byte[] data, DateTime ts,
            int off, int subtype, int rtLen)
        {
            switch (subtype)
            {
                case 8:  // Beacon
                case 5:  // Probe Response
                    var info = Parse80211Beacon(data, ts, rtLen);
                    if (info == null || string.IsNullOrEmpty(info.Bssid)) return;
                    _beacons[info.Bssid] = info;
                    // Rekisteröi avoin verkko DNS/TLS-analyysiin
                    if (info.Security == "Open")
                        _openNetworkBssids[info.Bssid] = true;
                    else
                        _openNetworkBssids.TryRemove(info.Bssid, out _);
                    _status = $"Passiivisesti: {_beacons.Count} AP:ta";
                    BeaconReceived?.Invoke(info);
                    break;

                case 10: // Disassociation
                case 12: // Deauthentication
                    // fc1 bit 6 = Protected Frame — välitetään PMF-ristikäyttöä varten
                    bool isProtectedMgmt = data.Length > off + 1 && (data[off + 1] & 0x40) != 0;
                    HandleDeauthFrame(data, off, subtype == 12, ts, isProtectedMgmt);
                    break;

                case 4:  // Probe Request — laite etsii tiettyä SSID:tä
                    if (off + 24 < data.Length)
                    {
                        string srcMac = FormatMac(data, off + 10);
                        string probed = ParseProbeRequestSsid(data, off + 24);
                        // ?.Invoke on atomiinen: ei race conditionia null-checkin ja kutsun välillä
                        if (!string.IsNullOrEmpty(probed))
                            ProbeRequestDetected?.Invoke(srcMac, probed, data, off);
                    }
                    break;

                case 0:  // Association Request — tulevaisuutta varten
                case 1:  // Association Response
                case 2:  // Reassociation Request
                case 3:  // Reassociation Response
                    // Failed Association -seuranta voidaan lisätä tänne
                    break;
            }
        }

        private void HandleDeauthFrame(byte[] data, int off, bool isDeauth,
            DateTime ts, bool isFrameProtected = false)
        {
            // Lähettäjä: Address 2 (bytes off+10..off+15)
            // Kohde:     Address 1 (bytes off+4..off+9)
            if (off + 24 > data.Length) return;

            string sender = FormatMac(data, off + 10);
            string target = FormatMac(data, off + 4);

            var evt = DeauthTracker.ParseFrame(data, off, sender, target,
                isDeauth, ts, isFrameProtected);
            DeauthReceived?.Invoke(evt);
        }

        // ── Control-kehykset (RTS/CTS) ────────────────────────────────

        private void HandleControlFrame(byte[] data, int off, int subtype)
        {
            // Kanavan selvitys: radiotap freq → kanava
            // Yksinkertaistettu: käytetään viimeksi parsittua kanavaa per BSSID
            // tai laskemme frekvenssin radiotapista (kts. Parse80211Beacon)
            switch (subtype)
            {
                case 11: RtsReceived?.Invoke(0); break; // kanava 0 = tuntematon
                case 12: CtsReceived?.Invoke(0); break;
            }
        }

        // ── Data-kehykset (DNS + TLS SNI) ────────────────────────────

        /// <summary>
        /// Tapahtuma kun EAPOL-protokollan kehys (EtherType 0x888E) havaitaan.
        /// Parametrit: (clientMac, bssidMac) — EapolTracker laskee eri AP:t per laite.
        /// EAPOL-Key-kehyksen kryptografisia kenttiä (nonce, MIC, Key Data) ei parsita.
        /// </summary>
        public event Action<string, string> EapolFrameDetected;

        private void HandleDataFrame(byte[] data, int off, int subtype, byte fc1)
        {
            if (off + 30 > data.Length) return;

            string bssid  = FormatMac(data, off + 16);
            string srcMac = FormatMac(data, off + 10);

            // 802.11 LLC/SNAP offset: MAC(24) + [QoS(2)] → LLC alkaa tässä
            bool isQos  = (subtype & 0x8) != 0;
            int  llcOff = off + 24 + (isQos ? 2 : 0);

            if (llcOff + 8 > data.Length) return;

            // Tarkista LLC/SNAP tunniste (AA AA 03 + 3B OUI + 2B EtherType)
            if (data[llcOff] != 0xAA || data[llcOff + 1] != 0xAA || data[llcOff + 2] != 0x03)
                return;

            ushort etherType = (ushort)((data[llcOff + 6] << 8) | data[llcOff + 7]);
            int payloadOff   = llcOff + 8;

            // ── EAPOL (EtherType 0x888E) — tunnistus riippumatta suojauksesta ──
            // 4-way handshaken Message 1 ja 2 lähetetään aina salaamattomina,
            // koska istuntoavain muodostuu vasta handshaken aikana.
            // Havaitsemme EAPOL-kättelyn käynnistymisen käyttäytymismallina
            // (kuinka monta eri AP:ta sama laite kättelee lyhyessä ajassa)
            // — emme parssi EAPOL-Key-kenttiä kryptografisten arvojen osalta.
            if (etherType == 0x888E)
            {
                EapolFrameDetected?.Invoke(srcMac, bssid);
                return;
            }

            // ── IPv4 (EtherType 0x0800) — vain avoimet verkot ──────────────
            bool isProtected = (fc1 & 0x40) != 0;
            if (isProtected) return;
            if (!_openNetworkBssids.ContainsKey(bssid)) return;
            if (etherType != 0x0800) return;

            if (payloadOff + 20 > data.Length) return;
            byte ipVer = (byte)((data[payloadOff] >> 4) & 0xF);
            if (ipVer != 4) return;

            // DNS
            string dns = HiddenNodeTracker.TryParseDnsQuery(data, payloadOff);
            if (dns != null)
            {
                DnsQueryDetected?.Invoke(dns, srcMac, bssid);
                return;
            }
            // TLS SNI
            string sni = HiddenNodeTracker.TryParseTlsSni(data, payloadOff);
            if (sni != null)
                TlsSniDetected?.Invoke(sni, srcMac, bssid);
        }

        // ── Beacon-parsinta (alkuperäinen + kyvykkyyslaajennus) ──────

        private static PassiveBeaconInfo Parse80211Beacon(byte[] data, DateTime ts, int rtLen)
        {
            try
            {
                if (data == null || data.Length < 36) return null;
                if (rtLen < 8 || rtLen >= data.Length) return null;

                uint present = (uint)(data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24));

                // Perus radiotap-kenttäparsinta (TSFT=0, Flags=1, Rate=2, Channel=3, FHSS=4, Signal=5)
                int[] fieldSizes = { 8, 1, 1, 4, 2, 1 };
                int[] alignSizes = { 8, 1, 1, 2, 2, 1 };

                int rssi         = -100;
                int frequencyMhz = 0;
                int fieldOff     = 8;

                for (int bit = 0; bit < fieldSizes.Length; bit++)
                {
                    if ((present & (1u << bit)) == 0) continue;
                    int align = alignSizes[bit];
                    if (align > 1 && (fieldOff % align) != 0)
                        fieldOff += align - (fieldOff % align);
                    if (fieldOff + fieldSizes[bit] > data.Length) break;
                    if (bit == 3) frequencyMhz = data[fieldOff] | (data[fieldOff + 1] << 8);
                    else if (bit == 5) rssi = (sbyte)data[fieldOff];
                    fieldOff += fieldSizes[bit];
                }

                // ── Radiotap-laajennukset: Rate (bit 2) ja Noise (bit 6) ──
                var (framRateMbps, noiseDdBm) = FrameCapabilityParser.ParseRadiotapExtras(
                    data, present, rtLen);

                int off = rtLen;
                if (off + 24 >= data.Length) return null;

                byte fc0 = data[off];
                if (((fc0 >> 2) & 0x3) != 0) return null;
                int fsubtype = (fc0 >> 4) & 0xF;
                if (fsubtype != 8 && fsubtype != 5) return null;

                int bssidOff = off + 16;
                if (bssidOff + 6 > data.Length) return null;
                string bssid = FormatMac(data, bssidOff);

                int beaconTu = 0;
                if (off + 24 + 10 <= data.Length)
                    beaconTu = data[off + 24 + 8] | (data[off + 24 + 9] << 8);

                int bodyOff = off + 24 + 12;
                if (bodyOff >= data.Length) return null;

                // ── IE-parsinta (perustiedot) ─────────────────────────
                string ssid = ""; int channel = 0; string security = "Open";
                int? channelUtilization = null;
                int? stationCount       = null;
                bool wpsEnabled         = false;
                int pos = bodyOff;

                while (pos + 1 < data.Length)
                {
                    byte tagId  = data[pos];
                    byte tagLen = data[pos + 1];
                    pos += 2;
                    if (pos + tagLen > data.Length) break;
                    switch (tagId)
                    {
                        case 0:
                            if (tagLen > 0)
                                try   { ssid = System.Text.Encoding.UTF8.GetString(data, pos, tagLen); }
                                catch { ssid = System.Text.Encoding.GetEncoding("iso-8859-1").GetString(data, pos, tagLen); }
                            break;
                        case 3:  if (tagLen == 1) channel = data[pos]; break;
                        case 11:
                            if (tagLen >= 5)
                            {
                                stationCount       = data[pos] | (data[pos + 1] << 8);
                                int rawUtil        = data[pos + 2];
                                channelUtilization = (rawUtil * 100) / 255;
                            }
                            break;
                        case 48: security = ParseRsnSecurity(data, pos, tagLen); break;
                        case 221:
                            if (tagLen >= 4 &&
                                data[pos] == 0x00 && data[pos+1] == 0x50 && data[pos+2] == 0xF2)
                            {
                                if (data[pos+3] == 0x01 && security == "Open") security = "WPA";
                                else if (data[pos+3] == 0x04) wpsEnabled = true;
                            }
                            break;
                    }
                    pos += tagLen;
                }

                var info = new PassiveBeaconInfo
                {
                    Bssid              = bssid,
                    Ssid               = ssid,
                    Channel            = channel,
                    Rssi               = rssi,
                    BeaconIntervalTu   = beaconTu,
                    Security           = security,
                    WpsEnabled         = wpsEnabled,
                    Seen               = ts,
                    ChannelUtilization = channelUtilization,
                    StationCount       = stationCount,
                    FrequencyMhz       = frequencyMhz,
                    NoisedBm           = noiseDdBm,
                    FrameRateMbps      = framRateMbps,
                };

                // ── IE-kyvykkyyslaajennukset (HT/VHT/HE, roaming) ────
                FrameCapabilityParser.ParseCapabilityIEs(data, bodyOff, data.Length, info);

                return info;
            }
            catch (Exception ex) { AppLogger.Log($"[Passive] Parsinta: {ex.Message}"); return null; }
        }

        private static string ParseRsnSecurity(byte[] data, int pos, int len)
        {
            try
            {
                if (len < 8) return "WPA2";
                int offset = pos + 2 + 4;
                if (offset + 2 > pos + len) return "WPA2";
                int pairwiseCount = data[offset] | (data[offset + 1] << 8);
                offset += 2 + pairwiseCount * 4;
                if (offset + 2 > pos + len) return "WPA2";
                int akmCount = data[offset] | (data[offset + 1] << 8);
                offset += 2;
                bool hasPsk = false, hasSae = false, hasEap = false;
                for (int i = 0; i < akmCount && offset + 4 <= pos + len; i++, offset += 4)
                {
                    byte t = data[offset + 3];
                    if (t == 2) hasPsk = true;
                    if (t == 8) hasSae = true;
                    if (t == 1) hasEap = true;
                }
                if (hasSae && hasPsk) return "WPA2/3";
                if (hasSae)           return "WPA3";
                if (hasEap)           return "WPA2-Ent";
                return                       "WPA2";
            }
            catch { return "WPA2"; }
        }

        private static string FormatMac(byte[] data, int off)
            => string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                data[off], data[off+1], data[off+2], data[off+3], data[off+4], data[off+5]);

        /// <summary>Parsii Probe Request -kehyksen SSID Information Elementistä (IE 0).</summary>
        private static string ParseProbeRequestSsid(byte[] data, int bodyOff)
        {
            if (bodyOff + 2 > data.Length) return "";
            if (data[bodyOff] != 0) return ""; // ei SSID-IE
            int len = data[bodyOff + 1];
            if (len == 0 || bodyOff + 2 + len > data.Length) return "";
            try { return System.Text.Encoding.UTF8.GetString(data, bodyOff + 2, len); }
            catch { return ""; }
        }

        public List<PassiveBeaconInfo> GetBeacons()
            => new List<PassiveBeaconInfo>(_beacons.Values);

        public PassiveBeaconInfo TryGet(string bssid)
            => bssid != null && _beacons.TryGetValue(bssid, out var v) ? v : null;

        public void Dispose() { }
    }

}
