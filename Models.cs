using System;
using System.Collections.Generic;

namespace WifiAnalyzerPro
{
    public class SignalPoint
    {
        public DateTime Time { get; set; }
        public int      Rssi { get; set; }
    }

    public class AccessPointSnapshot
    {
        public string   Bssid    { get; set; }
        public string   Ssid     { get; set; }
        public int      Rssi     { get; set; }
        public int      Channel  { get; set; }
        public string   Phy      { get; set; }
        public DateTime LastSeen { get; set; }
    }

    public class AnalyzedAccessPoint
    {
        public string   Bssid                { get; set; }
        public string   Ssid                 { get; set; }
        public int      Rssi                 { get; set; }
        public int      Channel              { get; set; }
        public string   Band                 { get; set; }
        public string   Phy                  { get; set; }
        public long     TrafficBytes         { get; set; }
        public string   Vendor               { get; set; }
        public bool     IsConnected          { get; set; }
        public string   Security             { get; set; }
        public int      CoChannelCount       { get; set; }
        public int      AdjacentOverlapCount { get; set; }
        public double   InterferencePenalty  { get; set; }
        public double   SignalTrend          { get; set; }
        public double   SignalJitter         { get; set; }
        public string   StabilityTag         { get; set; }
        public string   MeshNote             { get; set; }
        public double   Score                { get; set; }
        public string   Grade                { get; set; }
        public DateTime LastSeen             { get; set; }

        /// <summary>Kanavan käyttöaste (0..100 %), BSS Load IE 11. null = ei saatavilla.</summary>
        public int? ChannelUtilization { get; set; }

        // ── Kyvykkyystiedot (passiivinen skannaus) ────────────────
        /// <summary>Wi-Fi-sukupolvi: "Wi-Fi 4", "Wi-Fi 5", "Wi-Fi 6", "Wi-Fi 6E", "Wi-Fi 7".</summary>
        public string PhyGeneration     { get; set; }
        /// <summary>Teoreettinen maksiminopeus Mbps HT/VHT/HE-kyvykkyyksistä.</summary>
        public int?   MaxDataRateMbps  { get; set; }
        /// <summary>MIMO-spatiaalivirtojen lukumäärä.</summary>
        public int?   SpatialStreams    { get; set; }
        /// <summary>Suurin tuettu kanavaleveysmax MHz.</summary>
        public int?   ChannelWidthMhz  { get; set; }
        /// <summary>SNR (Signal-to-Noise Ratio) dB. null jos kohinataso ei ole saatavilla.</summary>
        public int?   SnrDb            { get; set; }

        // ── Roaming-standardit ────────────────────────────────────
        /// <summary>Tukee 802.11k (Radio Resource Management) -standardia.</summary>
        public bool   Supports80211k   { get; set; }
        /// <summary>Tukee 802.11v (BSS Transition Management) -standardia.</summary>
        public bool   Supports80211v   { get; set; }
        /// <summary>Tukee 802.11r (Fast BSS Transition) -standardia.</summary>
        public bool   Supports80211r   { get; set; }

        // ── PMF (Protected Management Frames / 802.11w) ───────────
        /// <summary>
        /// MFPC (Management Frame Protection Capable): AP tukee PMF:ää.
        /// RSN IE RSN Capabilities bit 7. WPA3 asettaa tämän aina.
        /// </summary>
        public bool PmfCapable  { get; set; }
        /// <summary>
        /// MFPR (Management Frame Protection Required): AP vaatii PMF:n kaikilta asiakkailta.
        /// RSN IE RSN Capabilities bit 6. WPA3-Personal = aina true.
        /// </summary>
        public bool PmfRequired { get; set; }
    }

    public class WifiFullReport
    {
        public DateTime                              Timestamp     { get; set; } = DateTime.Now;
        public string                                BestChannel2G { get; set; }
        public List<AnalyzedAccessPoint>             Networks      { get; set; }
        public Dictionary<string, List<SignalPoint>> History       { get; set; }
        public List<AlertEntry>                      Alerts        { get; set; }
    }

    public class AlertEntry
    {
        public DateTime Time    { get; set; }
        public string   Type    { get; set; }
        public string   Bssid   { get; set; }
        public string   Message { get; set; }
    }

    public class SpeedSample
    {
        public DateTime Time          { get; set; }
        public double   PingMs        { get; set; }
        public double   ThroughputKBs { get; set; }
        public string   Gateway       { get; set; }
    }

    public class NetworkDevice
    {
        public string   IpAddress  { get; set; }
        public string   MacAddress { get; set; }
        public string   Vendor     { get; set; }
        public string   Hostname   { get; set; }
        public DateTime LastSeen   { get; set; }
        public string   Source     { get; set; }
    }

    public class PassiveBeaconInfo
    {
        public string   Bssid            { get; set; }
        public string   Ssid             { get; set; }
        public int      Channel          { get; set; }
        public int      Rssi             { get; set; }
        public int      BeaconIntervalTu { get; set; }
        public string   Security         { get; set; }
        public bool     WpsEnabled       { get; set; }
        public DateTime Seen             { get; set; }

        /// <summary>Kanavan käyttöaste (0..100 %), BSS Load IE 11.</summary>
        public int? ChannelUtilization { get; set; }
        /// <summary>Assosioituneiden asiakkaiden määrä, BSS Load IE 11.</summary>
        public int? StationCount { get; set; }
        /// <summary>Taajuus MHz, radiotap Channel-kenttä. 0 = ei tiedossa.</summary>
        public int FrequencyMhz { get; set; }

        // ── Radiotap-laajennukset ─────────────────────────────────
        /// <summary>Kohinataso dBm (radiotap Antenna Noise, bit 6). null = ei tueta.</summary>
        public int? NoisedBm { get; set; }
        /// <summary>SNR = Rssi − NoisedBm. null jos kohinataso ei ole saatavilla.</summary>
        public int? SnrDb => (NoisedBm.HasValue && NoisedBm.Value != 0)
            ? Rssi - NoisedBm.Value : (int?)null;
        /// <summary>Kehyksen lähetysnopeus Mbps (radiotap Rate-kenttä × 0.5). null = ei parsittu.</summary>
        public double? FrameRateMbps { get; set; }

        // ── IE-kyvykkyyslaajennukset ──────────────────────────────
        /// <summary>Wi-Fi-sukupolvi ("Wi-Fi 4/5/6/6E/7"). null jos tunnistamaton.</summary>
        public string PhyGeneration { get; set; }
        /// <summary>Teoreettinen maksiminopeus Mbps (HT/VHT/HE MCS-taulukoista). null = ei parsittu.</summary>
        public int? MaxDataRateMbps { get; set; }
        /// <summary>Tuettu kanavaleveysmax MHz (20/40/80/160/320).</summary>
        public int? ChannelWidthMhz { get; set; }
        /// <summary>MIMO-spatiaalivirtojen lukumäärä (1–8). null = ei parsittu.</summary>
        public int? SpatialStreams { get; set; }
        /// <summary>802.11k Radio Resource Management -tuki (IE 70).</summary>
        public bool Supports80211k { get; set; }
        /// <summary>802.11v BSS Transition Management -tuki (Extended Capabilities, IE 127 byte 3 bit 3).</summary>
        public bool Supports80211v { get; set; }
        /// <summary>802.11r Fast BSS Transition -tuki (IE 55 tai MD IE 54).</summary>
        public bool Supports80211r { get; set; }

        /// <summary>AP tukee PMF:ää (MFPC=1 RSN Capabilities -kentässä).</summary>
        public bool   PmfCapable  { get; set; }
        /// <summary>AP vaatii PMF:n kaikilta asiakkailta (MFPR=1).</summary>
        public bool   PmfRequired { get; set; }
    }

    public class HourlyInterference
    {
        public int    Hour        { get; set; }
        public double AvgPenalty  { get; set; }
        public double MaxPenalty  { get; set; }
        public int    SampleCount { get; set; }
    }

    public class BeaconInfo
    {
        public string   Bssid       { get; set; }
        public int      IntervalTu  { get; set; }
        public double   IntervalMs  { get; set; }
        public string   LoadTag     { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    /// <summary>Yksittäisen kanavan spektridata-näkymää varten.</summary>
    public class ChannelEntry
    {
        public int                       Channel { get; set; }
        public string                    Band    { get; set; }
        public List<AnalyzedAccessPoint> Aps     { get; set; } = new();
    }

    /// <summary>DNS- tai TLS SNI -havainto avoimesta verkosta (DPI).</summary>
    public class TrafficObservation
    {
        public string   Name      { get; set; }
        public DateTime LastSeen  { get; set; }
        /// <summary>"DNS" tai "TLS-SNI".</summary>
        public string   Kind      { get; set; }
        public string   SourceMac { get; set; }
        public string   Bssid     { get; set; }
        /// <summary>Tunnistettu palvelu, esim. "Netflix", "Apple". null = tuntematon.</summary>
        public string   ServiceName      { get; set; }
        /// <summary>True jos domain löytyi blacklistiltä.</summary>
        public bool     IsBlacklisted    { get; set; }
        /// <summary>Blacklist-vakavuus: 1=seuranta, 2=epäilyttävä, 3=kriittinen/C2.</summary>
        public int      BlacklistSeverity { get; set; }
        /// <summary>Blacklist-syy, esim. "Emotet malware pattern".</summary>
        public string   BlacklistReason  { get; set; }
    }

    /// <summary>
    /// Strukturoitu Evil Twin -havainto dashboardia varten.
    /// Sisältää molemmat BSSID:t, vahvistusasteen ja syyn.
    /// </summary>
    public class EvilTwinAlert
    {
        public string   Ssid             { get; set; }
        public string   SuspectBssid     { get; set; }
        public string   LegitBssid       { get; set; }
        /// <summary>1=epäilty, 2=todennäköinen, 3=varmennettu (PMF+salaamaton).</summary>
        public int      ConfidenceLevel  { get; set; }
        /// <summary>Ihmisluettava syy: "eri valmistaja" / "heikompi salaus" / "PMF-hyökkäys".</summary>
        public string   Reason           { get; set; }
        public DateTime DetectedAt       { get; set; }
    }

    /// <summary>
    /// Deauthentication- tai Disassociation-kehystapahtuma.
    /// Käytetään DeauthTracker:issa hyökkäysten tunnistukseen.
    /// </summary>
    public class DeauthEvent
    {
        public DateTime Time          { get; set; }
        /// <summary>Kehyksen lähettäjä (AP tai hyökkääjä).</summary>
        public string   SenderBssid   { get; set; }
        /// <summary>Kohde-MAC (FF:FF:FF:FF:FF:FF = broadcast = kaikki asiakkaat).</summary>
        public string   TargetMac     { get; set; }
        /// <summary>True = Deauth (12), False = Disassoc (10).</summary>
        public bool     IsDeauth      { get; set; }
        /// <summary>802.11 Reason Code (1=Unspecified, 7=Auth timeout jne.).</summary>
        public ushort   ReasonCode    { get; set; }
        public string   ReasonText    { get; set; }
        /// <summary>True jos broadcast — yksi kehys irrottaa KAIKKI asiakkaat.</summary>
        public bool     IsBroadcast   { get; set; }
        /// <summary>
        /// True jos 802.11 FC:n Protected Frame -bitti on asetettu (fc1 bit 6).
        /// Jos BSSID tukee PMF (PmfCapable) mutta tämä on false → VARMENNETTU HYÖKKÄYS.
        /// </summary>
        public bool     IsFrameProtected { get; set; }
    }

    /// <summary>RTS/CTS-seurannasta laskettava hidden node -tilasto per kanava.</summary>
    public class HiddenNodeStat
    {
        public int    Channel        { get; set; }
        public int    RtsCount       { get; set; }
        public int    CtsCount       { get; set; }
        /// <summary>RTS:t joihin ei tullut CTS-vastausta — mahdollinen piilotettu solmu.</summary>
        public int    MissedCts      { get; set; }
        /// <summary>CTS-vasteprosentti 0–100 %.</summary>
        public double CtsResponsePct =>
            RtsCount > 0 ? Math.Round(CtsCount * 100.0 / RtsCount, 1) : 100.0;
        public bool   HiddenNodeSuspected => MissedCts > 10 && CtsResponsePct < 70;
    }
    /// <summary>
    /// EAPOL-Key-kehyshavainto — 4-way handshaken tunnistamiseen ja
    /// PMKID-keräilyhyökkäyksen havaitsemiseen.
    ///
    /// Hyökkäysmalli (Jens Steube 2018): hyökkääjä pakottaa AP:n
    /// lähettämään EAPOL-Key Message 1 -kehyksen ilman yhdistynyttä asiakaslaitetta.
    /// Havaitsemme hyökkäysmallin (monta eri BSSID:tä lyhyessä ajassa)
    /// — emme tallenna PMKID-tiivistettä itsessään.
    /// </summary>
    public class EapolEvent
    {
        public DateTime Time           { get; set; } = DateTime.Now;
        /// <summary>Asiakkaan MAC-osoite (Address2 / STA).</summary>
        public string   ClientMac      { get; set; }
        /// <summary>AP:n BSSID (Address3).</summary>
        public string   BssidMac       { get; set; }
        /// <summary>4-way handshaken viestin numero 1–4. 0 = ei tunnistettu.</summary>
        public int      MessageNumber  { get; set; }
        /// <summary>True jos Message 1:n Key Data -osio sisältää PMKID-kentän.</summary>
        public bool     HasPmkid       { get; set; }
        /// <summary>True jos havaitsemishetkellä arvioidaan hyökkäysmallia.</summary>
        public bool     IsLikelyAttack { get; set; }
        public string   Detail         { get; set; }
    }
}