using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    // ═══════════════════════════════════════════════════════════
    // LAITETUNNISTUS (ARP + mDNS)
    // ═══════════════════════════════════════════════════════════

    public class DeviceScanner : IDisposable
    {
        // Kilpatilanteen esto: Interlocked.CompareExchange takaa että vain yksi skannaus kerrallaan
        private int _scanGuard;

        private static readonly System.Text.RegularExpressions.Regex _macRegex =
            new(@"([0-9a-f]{2}[-:]){5}[0-9a-f]{2}",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase |
                System.Text.RegularExpressions.RegexOptions.Compiled);

        private readonly ConcurrentDictionary<string, NetworkDevice> _devices =
            new ConcurrentDictionary<string, NetworkDevice>(StringComparer.OrdinalIgnoreCase);
        private volatile string _status    = "Ei käynnissä";
        private volatile bool   _scanning;
        private Thread          _mdnsThread;
        private volatile bool   _mdnsRunning;
        // Valinnainen OUI-haku — null = Vendor jää tyhjäksi
        private readonly OuiDatabase _oui;

        public string Status     => _status;
        public bool   IsScanning => _scanning;

        /// <param name="oui">OUI-tietokanta vendor-hakua varten (null = Vendor jää tyhjäksi)</param>
        public DeviceScanner(OuiDatabase oui = null) => _oui = oui;

        public void StartArpScan(string subnet)
        {
            if (Interlocked.CompareExchange(ref _scanGuard, 1, 0) != 0) return;
            new Thread(() => ArpScanLoop(subnet)) { IsBackground = true, Name = "ArpScanner" }.Start();
        }

        private void ArpScanLoop(string subnet)
        {
            _scanning = true;
            _status   = "ARP-skannaus käynnissä...";
            try
            {
                string[] parts = subnet.Split('.');
                if (parts.Length < 3) { _status = "Virheellinen subnet"; return; }
                string prefix = $"{parts[0]}.{parts[1]}.{parts[2]}.";
                int found = 0;

                Parallel.For(1, 255, new ParallelOptions { MaxDegreeOfParallelism = 32 }, i =>
                {
                    if (!_scanning) return;
                    string ip = prefix + i;
                    try
                    {
                        using var ping = new System.Net.NetworkInformation.Ping();
                        var reply = ping.Send(ip, 300);
                        if (reply.Status != System.Net.NetworkInformation.IPStatus.Success) return;
                        string mac      = GetMacFromArpCache(ip);
                        string vendor   = _oui?.Lookup(mac) ?? "";
                        string hostname = "";
                        try { hostname = System.Net.Dns.GetHostEntry(ip).HostName; } catch { }
                        _devices[ip] = new NetworkDevice
                        {
                            IpAddress = ip, MacAddress = mac, Vendor = vendor,
                            Hostname = hostname, LastSeen = DateTime.Now, Source = "ARP"
                        };
                        _status = $"ARP: löytyi {Interlocked.Increment(ref found)} laitetta... ({ip})";
                    }
                    catch (Exception ex) { AppLogger.Log($"[ARP] {ip}: {ex.Message}"); }
                });
                _status = $"ARP valmis: {found} laitetta löytyi";
            }
            catch (Exception ex) { _status = "ARP-virhe: " + ex.Message; }
            finally               { _scanning = false; Interlocked.Exchange(ref _scanGuard, 0); }
        }

        private static string GetMacFromArpCache(string ip)
        {
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo("arp", "-a " + ip)
                    { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = System.Diagnostics.Process.Start(psi);
                var match = _macRegex.Match(proc.StandardOutput.ReadToEnd());
                if (match.Success) return match.Value.Replace('-', ':').ToUpper();
            }
            catch (Exception ex) { AppLogger.Log($"[ARP] Cache {ip}: {ex.Message}"); }
            return "??:??:??:??:??:??";
        }

        public void StartMdnsListener()
        {
            if (_mdnsRunning) return;
            _mdnsRunning = true;
            _mdnsThread  = new Thread(MdnsLoop) { IsBackground = true, Name = "mDNS" };
            _mdnsThread.Start();
        }

        private void MdnsLoop()
        {
            try
            {
                var groupAddr = System.Net.IPAddress.Parse("224.0.0.251");
                using var udp = new System.Net.Sockets.UdpClient();
                udp.Client.SetSocketOption(System.Net.Sockets.SocketOptionLevel.Socket,
                    System.Net.Sockets.SocketOptionName.ReuseAddress, true);
                udp.Client.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Any, 5353));
                udp.JoinMulticastGroup(groupAddr);
                udp.Client.ReceiveTimeout = 2000;

                while (_mdnsRunning)
                {
                    try
                    {
                        var ep   = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0);
                        byte[] d = udp.Receive(ref ep);
                        if (d == null) continue;
                        string ip       = ep.Address.ToString();
                        string hostname = ParseMdnsHostname(d);
                        if (string.IsNullOrEmpty(ip)) continue;
                        _devices.AddOrUpdate(ip,
                            _ => new NetworkDevice { IpAddress = ip, MacAddress = "", Hostname = hostname,
                                                     Vendor = "", LastSeen = DateTime.Now, Source = "mDNS" },
                            (_, ex) => { ex.LastSeen = DateTime.Now;
                                         if (!string.IsNullOrEmpty(hostname) && string.IsNullOrEmpty(ex.Hostname)) ex.Hostname = hostname;
                                         return ex; });
                    }
                    catch (System.Net.Sockets.SocketException) { }
                    catch (Exception ex) { AppLogger.Log($"[mDNS] Virhe: {ex.Message}"); }
                }
            }
            catch (Exception ex) { AppLogger.Log($"[mDNS] Kuuntelu: {ex.Message}"); }
        }

        private static string ParseMdnsHostname(byte[] data)
        {
            try
            {
                if (data == null || data.Length < 13) return "";
                int pos = 12; var sb = new System.Text.StringBuilder();
                while (pos < data.Length)
                {
                    int len = data[pos++];
                    if (len == 0 || len > 63 || pos + len > data.Length) break;
                    if (sb.Length > 0) sb.Append('.');
                    sb.Append(System.Text.Encoding.ASCII.GetString(data, pos, len));
                    pos += len;
                }
                return sb.ToString();
            }
            catch { return ""; }
        }

        public List<NetworkDevice> GetDevices() => new List<NetworkDevice>(_devices.Values);
        public void Stop()    { _scanning = false; _mdnsRunning = false; }
        public void Dispose() { Stop(); try { _mdnsThread?.Join(500); } catch { } }
    }
}
