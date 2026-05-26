using System;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Parsii 802.11 Beacon- ja Probe Response -kehysten kyvykkyyskentät:
    ///   • HT Capabilities   (IE 45)   — Wi-Fi 4 / 802.11n
    ///   • VHT Capabilities  (IE 191)  — Wi-Fi 5 / 802.11ac
    ///   • HE Capabilities   (IE 255, Ext ID 35) — Wi-Fi 6/6E / 802.11ax
    ///   • EHT Capabilities  (IE 255, Ext ID 108) — Wi-Fi 7 / 802.11be
    ///   • 802.11r Fast BSS Transition (IE 55 tai MD IE 54)
    ///   • 802.11k Radio Resource Management (IE 70)
    ///   • 802.11v BSS Transition (Extended Capabilities IE 127, byte 3 bit 3)
    ///
    /// Lisäksi parsii radiotap-otsikon laajennettuja kenttiä:
    ///   • Bit 2: Rate (0.5 Mbps yksikkö)
    ///   • Bit 6: Antenna Noise (signed dBm)
    /// </summary>
    public static class FrameCapabilityParser
    {
        // ── Radiotap ─────────────────────────────────────────────────

        /// <summary>
        /// Parsii radiotap-otsikosta Rate (bit 2) ja Noise (bit 6) perusparserin
        /// jälkeen. Perusparseri hoitaa TSFT (0), Flags (1), Channel (3), Signal (5).
        ///
        /// Kenttäkoot ja tasaukset (bitti → koko, tasaus):
        ///   0 TSFT         8 B, align 8
        ///   1 Flags        1 B
        ///   2 Rate         1 B  ← arvo × 0.5 Mbps
        ///   3 Channel      4 B, align 2
        ///   4 FHSS         2 B
        ///   5 AntennaSignal 1 B  ← RSSI (jo parsittu)
        ///   6 AntennaNoise  1 B  ← kohinataso dBm
        ///   7 LockQuality  2 B, align 2
        ///   8 TxAttenuation 2 B
        ///   9 dB TxAtten   2 B
        ///  10 dBm TxPower  1 B
        ///  11 Antenna      1 B
        ///  12 dB AntennaSignal 1 B
        ///  13 dB AntennaNoise  1 B
        /// </summary>
        public static (double? rateMbps, int? noiseDdBm) ParseRadiotapExtras(
            byte[] data, uint present, int rtLen)
        {
            // Kenttäkoko- ja tasaustaulukot biteille 0..13
            int[] sizes  = { 8, 1, 1, 4, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1 };
            int[] aligns = { 8, 1, 1, 2, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1 };

            double? rate  = null;
            int?    noise = null;
            int     off   = 8; // radiotap-otsikko alkaa tavusta 0, data alkaa tavusta 8

            for (int bit = 0; bit < sizes.Length; bit++)
            {
                if ((present & (1u << bit)) == 0) continue;
                int align = aligns[bit];
                if (align > 1 && (off % align) != 0)
                    off += align - (off % align);
                if (off + sizes[bit] > rtLen || off + sizes[bit] > data.Length) break;

                switch (bit)
                {
                    case 2:
                        // Rate: 0.5 Mbps yksikkö. Arvo 0 = ei tiedossa.
                        byte rawRate = data[off];
                        if (rawRate > 0) rate = rawRate * 0.5;
                        break;
                    case 6:
                        // Antenna Noise: signed dBm. 0 = ei tueta (monilla ajureilla).
                        int n = (sbyte)data[off];
                        if (n != 0 && n > -120 && n < 0) noise = n;
                        break;
                }
                off += sizes[bit];
            }
            return (rate, noise);
        }

        // ── Information Element -parsinta ────────────────────────────

        /// <summary>
        /// Parsii kaikki kyvykkyyteen liittyvät IE-kentät beacon frame bodysta.
        /// Täydentää PassiveBeaconInfo:n kyvykkyyskentät.
        /// </summary>
        public static void ParseCapabilityIEs(
            byte[] data, int bodyOff, int dataEnd,
            PassiveBeaconInfo info)
        {
            bool hasHt  = false;
            bool hasVht = false;
            bool hasHe  = false;
            bool hasEht = false;

            int pos = bodyOff;
            while (pos + 1 < dataEnd)
            {
                byte tagId  = data[pos];
                int  tagLen = data[pos + 1];
                pos += 2;
                if (pos + tagLen > dataEnd) break;

                switch (tagId)
                {
                    case 45:  // HT Capabilities (802.11n / Wi-Fi 4)
                        if (tagLen >= 26) { ParseHtCapabilities(data, pos, tagLen, info); hasHt = true; }
                        break;

                    case 48:  // RSN Information Element — tietoturva + PMF
                        if (tagLen >= 4) ParseRsnCapabilities(data, pos, tagLen, info);
                        break;

                    case 55:  // Fast BSS Transition (802.11r)
                    case 54:  // Mobility Domain Element (802.11r)
                        info.Supports80211r = true;
                        break;

                    case 70:  // RRM Enabled Capabilities (802.11k)
                        if (tagLen >= 5) info.Supports80211k = true;
                        break;

                    case 127: // Extended Capabilities
                        if (tagLen >= 4)
                        {
                            if ((data[pos + 3] & 0x08) != 0) info.Supports80211v = true;
                            if (tagLen >= 5 && (data[pos + 4] & 0x40) != 0) info.Supports80211r = true;
                        }
                        break;

                    case 191: // VHT Capabilities (802.11ac / Wi-Fi 5)
                        if (tagLen >= 12) { ParseVhtCapabilities(data, pos, tagLen, info); hasVht = true; }
                        break;

                    case 255: // Extension element — HE (Wi-Fi 6) ja EHT (Wi-Fi 7)
                        if (tagLen >= 1)
                        {
                            byte extId = data[pos];
                            if (extId == 35 && tagLen >= 6)
                            {
                                ParseHeCapabilities(data, pos + 1, tagLen - 1, info);
                                hasHe = true;
                            }
                            else if (extId == 108 && tagLen >= 2)
                            {
                                hasEht = true;
                                if (!info.MaxDataRateMbps.HasValue)
                                    info.MaxDataRateMbps = EstimateMaxRate("EHT",
                                        info.ChannelWidthMhz ?? 320, info.SpatialStreams ?? 1);
                            }
                        }
                        break;
                }
                pos += tagLen;
            }

            if (hasEht)
                info.PhyGeneration = "Wi-Fi 7";
            else if (hasHe)
                info.PhyGeneration = info.FrequencyMhz >= 5925 ? "Wi-Fi 6E" : "Wi-Fi 6";
            else if (hasVht)
                info.PhyGeneration = "Wi-Fi 5";
            else if (hasHt)
                info.PhyGeneration = "Wi-Fi 4";

            // WPA3 vaatii aina PMF — lisätarkistus johdonmukaisuudelle
            if (info.Security != null && info.Security.Contains("3") && !info.PmfCapable)
                info.PmfCapable = true; // WPA3 implisoi PMF:n
        }

        // ── RSN Capabilities — PMF (Protected Management Frames) ────

        /// <summary>
        /// Parsii RSN Information Element -kentän RSN Capabilities -tavut (2 B).
        /// 802.11-2020 §9.4.2.24, RSN Capabilities:
        ///
        ///   Bit 0:   Pre-Authentication
        ///   Bit 1:   No Pairwise
        ///   Bit 2-3: PTKSA Replay Counter
        ///   Bit 4-5: GTKSA Replay Counter
        ///   Bit 6:   MFPR (Management Frame Protection Required)  ← WPA3 = aina 1
        ///   Bit 7:   MFPC (Management Frame Protection Capable)   ← WPA3 = aina 1
        ///   Bit 8:   PEERKEY Enabled
        ///   Bit 9:   SPP A-MSDU Capable
        ///   Bit 10:  SPP A-MSDU Required
        ///
        /// Jos MFPR=1 ja saadaan salaamaton Deauth → VARMENNETTU hyökkäys.
        /// Jos MFPC=1 ja saadaan salaamaton Deauth → TODENNÄKÖINEN hyökkäys.
        /// </summary>
        private static void ParseRsnCapabilities(byte[] data, int pos, int len, PassiveBeaconInfo info)
        {
            // RSN IE rakenne:
            //   Version (2) + GroupCipher (4) + PairwiseCount (2) + Pairwise (4×n)
            //   + AKMCount (2) + AKM (4×n) + RSN Capabilities (2) [+ PMKID ...]
            try
            {
                int off = pos;
                if (off + 2 > pos + len) return;
                // ushort version = (ushort)(data[off] | (data[off+1] << 8));
                off += 2; // Version

                if (off + 4 > pos + len) return;
                off += 4; // Group Cipher Suite

                if (off + 2 > pos + len) return;
                int pairwiseCount = data[off] | (data[off + 1] << 8);
                off += 2 + pairwiseCount * 4;

                if (off + 2 > pos + len) return;
                int akmCount = data[off] | (data[off + 1] << 8);
                off += 2 + akmCount * 4;

                // RSN Capabilities: 2 tavua
                if (off + 2 > pos + len) return;
                ushort caps = (ushort)(data[off] | (data[off + 1] << 8));

                info.PmfRequired = (caps & 0x0040) != 0; // bit 6 = MFPR
                info.PmfCapable  = (caps & 0x0080) != 0; // bit 7 = MFPC

                // MFPR implisoi MFPC — korjaa epäjohdonmukaisia AP-toteutuksia
                if (info.PmfRequired && !info.PmfCapable)
                    info.PmfCapable = true;
            }
            catch { /* Virheellinen IE-muoto — jätetään oletusarvoihin */ }
        }

        // ── HT Capabilities (IE 45, 802.11n) ────────────────────────

        private static void ParseHtCapabilities(byte[] data, int off, int len, PassiveBeaconInfo info)
        {
            // HT Capabilities Info: 2 tavua
            ushort htCap = (ushort)(data[off] | (data[off + 1] << 8));

            // Bit 1: Supported Channel Width Set (0=20MHz vain, 1=40MHz tuki)
            bool supports40 = (htCap & 0x02) != 0;

            // Kanavaleveydeksi asetetaan 40 vain jos ei isompi jo asetettu
            if (!info.ChannelWidthMhz.HasValue || info.ChannelWidthMhz < 40)
                info.ChannelWidthMhz = supports40 ? 40 : 20;

            // MCS Set (10 tavua alkaen offsetista 3)
            if (off + 3 + 10 <= off + len)
            {
                int streams = 0;
                // Kukin tavu (0–3) vastaa yhtä spatiaalivirta-indexiä
                // Jos tavu on nollasta eriävä → virta tuettu
                for (int i = 0; i < 4; i++)
                    if (data[off + 3 + i] != 0) streams = i + 1;

                if (streams > 0)
                    info.SpatialStreams = streams;

                // Arvioi maksiminopeus HT-taulukon mukaan (MCS 7 / MCS 15 / jne.)
                int width  = supports40 ? 40 : 20;
                int rate   = EstimateMaxRate("HT", width, streams > 0 ? streams : 1);
                if (!info.MaxDataRateMbps.HasValue || info.MaxDataRateMbps < rate)
                    info.MaxDataRateMbps = rate;
            }
        }

        // ── VHT Capabilities (IE 191, 802.11ac) ─────────────────────

        private static void ParseVhtCapabilities(byte[] data, int off, int len, PassiveBeaconInfo info)
        {
            // VHT Capabilities Info: 4 tavua
            uint vhtCap = (uint)(data[off] | (data[off+1]<<8) | (data[off+2]<<16) | (data[off+3]<<24));

            // Bits 2–3: Supported Channel Width Set
            int cwSet = (int)((vhtCap >> 2) & 0x3);
            int width = cwSet switch { 0 => 80, 1 => 160, 2 => 80, _ => 80 }; // 2=80+80
            if (!info.ChannelWidthMhz.HasValue || info.ChannelWidthMhz < width)
                info.ChannelWidthMhz = width;

            // Tx MCS Map: 16 bittiä (offset 8), 2 bittiä per virta (8 virtaa)
            if (off + 10 <= off + len)
            {
                ushort txMcsMap = (ushort)(data[off + 8] | (data[off + 9] << 8));
                int streams = 0;
                for (int s = 0; s < 8; s++)
                {
                    int mcs = (txMcsMap >> (s * 2)) & 0x3;
                    if (mcs != 0x3) streams = s + 1; // 0x3 = Not supported
                }
                if (streams > 0 && (!info.SpatialStreams.HasValue || info.SpatialStreams < streams))
                    info.SpatialStreams = streams;

                int rate = EstimateMaxRate("VHT", width, streams > 0 ? streams : 1);
                if (!info.MaxDataRateMbps.HasValue || info.MaxDataRateMbps < rate)
                    info.MaxDataRateMbps = rate;
            }
        }

        // ── HE Capabilities (IE 255 ExtID 35, 802.11ax) ─────────────

        private static void ParseHeCapabilities(byte[] data, int off, int len, PassiveBeaconInfo info)
        {
            // HE Capabilities Element rakenne (offset suhteessa ExtID-tavun jälkeen):
            // [0-5]:  HE MAC Capabilities
            // [6-10]: HE PHY Capabilities
            // Byte 6 (PHY index 0), bit 1: Channel Width Set muuttujat
            if (len < 7) return;

            byte phyCap0 = data[off + 6]; // PHY Capabilities byte 0
            // Bits 1-7: tuetut kanavaleveyskombinaatiot
            bool has40_80_24g = (phyCap0 & 0x02) != 0;
            bool has40_80     = (phyCap0 & 0x04) != 0;
            bool has160       = (phyCap0 & 0x08) != 0;
            bool has80p80     = (phyCap0 & 0x10) != 0;

            int width = (has160 || has80p80) ? 160 : has40_80 ? 80 : 40;
            if (!info.ChannelWidthMhz.HasValue || info.ChannelWidthMhz < width)
                info.ChannelWidthMhz = width;

            // Tx HE-MCS and NSS Set: 2+2 tavua (eri formaatti kuin VHT)
            // Yksinkertaistettu: käytetään spatiaalivirrat aiemmasta VHT/HT parsinnasta
            int streams = info.SpatialStreams ?? 1;

            int rate = EstimateMaxRate("HE", width, streams);
            if (!info.MaxDataRateMbps.HasValue || info.MaxDataRateMbps < rate)
                info.MaxDataRateMbps = rate;
        }

        // ── Nopeus-estimaattitaulukko ────────────────────────────────

        /// <summary>
        /// Arvioi teoreettisen maksiminopeus Mbps PHY-tyypin, kanavaleveydell ja
        /// spatiaalivirtojen perusteella. Käyttää MCS-maksimia (MCS 9 / MCS 11).
        ///
        /// Lähteet: IEEE 802.11-2020, taulukot 19-49 (HT), 21-26 (VHT), 27-50 (HE).
        /// 800 ns guard interval. Pyöristetty lähimpään 10 Mbps:iin.
        /// </summary>
        public static int EstimateMaxRate(string phy, int channelWidthMhz, int streams)
        {
            streams = Math.Max(1, Math.Min(8, streams));
            switch (phy)
            {
                case "HT":
                    // MCS 7 per virta
                    int htBase = channelWidthMhz >= 40 ? 150 : 72;
                    return htBase * streams;

                case "VHT":
                    // MCS 9 per virta (joitain yhdistelmiä ei tue MCS9 — konservatiivinen)
                    int vhtBase = channelWidthMhz >= 160 ? 867 : channelWidthMhz >= 80 ? 433 : 200;
                    return vhtBase * streams;

                case "HE":
                    // MCS 11 (1024-QAM), 0.8 µs GI
                    int heBase = channelWidthMhz >= 160 ? 1201 : channelWidthMhz >= 80 ? 600 :
                                 channelWidthMhz >= 40  ? 287  : 143;
                    return heBase * streams;

                case "EHT":
                    // MCS 13 (4096-QAM), 320 MHz 6 GHz
                    int ehtBase = channelWidthMhz >= 320 ? 2882 : channelWidthMhz >= 160 ? 1441 :
                                  channelWidthMhz >= 80  ? 720  : 360;
                    return ehtBase * streams;

                default:
                    return 0;
            }
        }
    }
}
