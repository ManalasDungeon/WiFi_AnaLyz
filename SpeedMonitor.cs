using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace WifiAnalyzerPro
{
    public class SpeedMonitor : IDisposable
    {
        private readonly ConcurrentQueue<SpeedSample> _samples = new();
        private readonly CancellationTokenSource      _cts     = new();
        private volatile string                       _status       = "Ei käynnissä";
        private volatile SpeedSample                  _latestSample;
        private Task                                  _task;

        private static readonly HttpClient _httpClient =
            new() { Timeout = TimeSpan.FromSeconds(35) };

        private const int MaxSamples = 60;
        private string _testUrl      = "http://speedtest.tele2.net/1MB.zip";
        private int    _intervalSec  = 30;
        private int    _dlEveryTick  = 10;   // nopeustesti joka 10. ping-kierros

        public string Status => _status;

        public void Start(string gatewayIp, WifiConfig cfg)
        {
            if (cfg != null)
            {
                if (!string.IsNullOrWhiteSpace(cfg.SpeedTestUrl)) _testUrl = cfg.SpeedTestUrl;
                _intervalSec = Math.Max(10, cfg.SpeedTestIntervalMinutes * 60 / 10);
                _dlEveryTick = Math.Max(2,  cfg.SpeedTestIntervalMinutes * 2);
            }
            _task = Task.Run(() => MeasureLoopAsync(gatewayIp, _cts.Token));
        }

        private async Task MeasureLoopAsync(string gateway, CancellationToken ct)
        {
            int tick = 1;
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    double pingMs = await MeasurePingAsync(gateway, ct).ConfigureAwait(false);
                    _status = $"Ping {gateway}: {(pingMs < 0 ? "aikakatkaisu" : $"{pingMs:F0} ms")}";

                    double throughput = 0;
                    if (tick % _dlEveryTick == 0)
                    {
                        _status    = "Nopeusmittaus käynnissä...";
                        throughput = await MeasureThroughputAsync(_testUrl, ct).ConfigureAwait(false);
                        _status    = $"Ping {gateway}: {pingMs:F0} ms | DL: {throughput:F0} KB/s";
                    }

                    var sample = new SpeedSample
                        { Time = DateTime.Now, PingMs = pingMs, ThroughputKBs = throughput, Gateway = gateway };
                    _samples.Enqueue(sample);
                    _latestSample = sample;

                    // KORJAUS: ConcurrentQueue.Count on O(n); aiempi `while (_samples.Count > MaxSamples)`
                    // teki O(n²) työn per push. Snapshottaa kerran ja dequeue ylimäärä.
                    int excess = _samples.Count - MaxSamples;
                    for (int i = 0; i < excess; i++)
                        if (!_samples.TryDequeue(out _)) break;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { AppLogger.Log($"[Speed] Loop: {ex.Message}"); }

                tick++;
                try { await Task.Delay(TimeSpan.FromSeconds(_intervalSec), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private static async Task<double> MeasurePingAsync(string host, CancellationToken ct)
        {
            try
            {
                using var ping = new System.Net.NetworkInformation.Ping();
                var replyTask = ping.SendPingAsync(host, 2000);
                var done      = await Task.WhenAny(replyTask, Task.Delay(2500, ct)).ConfigureAwait(false);
                if (done != replyTask) return -1;
                var reply = await replyTask.ConfigureAwait(false);
                return reply.Status == System.Net.NetworkInformation.IPStatus.Success
                    ? reply.RoundtripTime : -1;
            }
            catch { return -1; }
        }

        /// <summary>
        /// KORJAUS: streaming-luku — ei puskuroida koko tiedostoa muistiin.
        /// Lataus-ajan mittaus alkaa vastauksen alusta, ei pyynnön lähetyksestä,
        /// mikä antaa tarkemman throughput-arvon hitaalla yhteydellä.
        /// </summary>
        private static async Task<double> MeasureThroughputAsync(string testUrl, CancellationToken ct)
        {
            try
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                linked.CancelAfter(TimeSpan.FromSeconds(30));

                using var response = await _httpClient
                    .GetAsync(testUrl, HttpCompletionOption.ResponseHeadersRead, linked.Token)
                    .ConfigureAwait(false);
                response.EnsureSuccessStatusCode();

                // KORJAUS: parametriton ReadAsStreamAsync + byte[]-ReadAsync —
                // toimii .NET Framework 4.5+:lla ja kaikilla .NET Core / .NET 5+ -versioilla.
                // CancellationToken vaikuttaa silti varsinaisiin ReadAsync-kutsuihin.
                using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                var buf  = new byte[8192];
                long total = 0;
                var sw   = System.Diagnostics.Stopwatch.StartNew();
                int read;
                while ((read = await stream.ReadAsync(buf, 0, buf.Length, linked.Token).ConfigureAwait(false)) > 0)
                    total += read;
                sw.Stop();

                if (total == 0 || sw.ElapsedMilliseconds == 0) return 0;
                return (total / 1024.0) / (sw.ElapsedMilliseconds / 1000.0);
            }
            catch (OperationCanceledException) { return 0; }
            catch (Exception ex) { AppLogger.Log($"[Speed] Throughput: {ex.Message}"); return 0; }
        }

        public SpeedSample GetLatest() => _latestSample;
        public IEnumerable<SpeedSample> GetSamples() => _samples;

        /// <summary>
        /// Jokainen rivi on oma alkio palautustaulukossa.
        /// </summary>
        public string[] GetPingChart(int width = 40)
            => SignalChartRenderer.GetPingChart(_samples, width);

        public void Stop()    => _cts.Cancel();
        public void Dispose() { _cts.Cancel(); try { _task?.Wait(500); } catch { } _cts.Dispose(); }
    }
}
