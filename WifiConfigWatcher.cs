using System;
using System.IO;
using System.Threading;

namespace WifiAnalyzerPro
{
    /// <summary>
    /// Seuraa wifi_config.json -tiedoston muutoksia FileSystemWatcherilla.
    /// Kun tiedosto muuttuu, ladataan uusi konfiguraatio ja kutsutaan OnChanged-callback.
    /// </summary>
    public sealed class WifiConfigWatcher : IDisposable
    {
        private readonly FileSystemWatcher _fsw;
        private readonly Action<WifiConfig> _onChanged;
        // Interlocked-käyttö: DateTime ei ole atomiinen 32-bittisillä alustoilla
        private long _lastFiredTicks = DateTime.MinValue.Ticks;
        private const int DebounceMs = 500; // odota kirjoituksen loppumista

        public bool IsActive => _fsw?.EnableRaisingEvents == true;

        /// <param name="configPath">Konfiguraatiotiedoston täydellinen polku</param>
        /// <param name="onChanged">Callback kun uusi konfiguraatio on ladattu</param>
        public WifiConfigWatcher(string configPath, Action<WifiConfig> onChanged)
        {
            _onChanged = onChanged ?? throw new ArgumentNullException(nameof(onChanged));

            string dir  = Path.GetDirectoryName(Path.GetFullPath(configPath)) ?? ".";
            string file = Path.GetFileName(configPath);

            try
            {
                _fsw = new FileSystemWatcher(dir, file)
                {
                    NotifyFilter         = NotifyFilters.LastWrite | NotifyFilters.Size,
                    EnableRaisingEvents  = true,
                    IncludeSubdirectories = false
                };
                _fsw.Changed += OnFileChanged;
                AppLogger.Log($"[HotReload] Seuraa: {configPath}");
            }
            catch (Exception ex)
            {
                AppLogger.Log($"[HotReload] Ei voitu käynnistää: {ex.Message}");
            }
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            // Debounce: FileSystemWatcher voi laukaista useaan kertaan yhdestä tallennuksesta.
            // Interlocked.Read/Exchange: DateTime.Ticks on long (64-bit) → tarvitaan Interlocked
            // 32-bittisillä alustoilla, joilla 64-bit-kirjoitus ei ole atomiinen.
            long nowTicks  = DateTime.Now.Ticks;
            long lastTicks = Interlocked.Read(ref _lastFiredTicks);
            if (new TimeSpan(nowTicks - lastTicks).TotalMilliseconds < DebounceMs) return;
            Interlocked.Exchange(ref _lastFiredTicks, nowTicks);

            // Aja taustasäikeessä — ei blokoi tiedostojärjestelmää
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                Thread.Sleep(DebounceMs); // odota vielä että kirjoitus varmasti valmis
                try
                {
                    var newCfg = WifiConfigLoader.Load(e.FullPath);
                    var warnings = WifiConfigLoader.Validate(newCfg);
                    if (warnings.Count > 0)
                        foreach (var w in warnings)
                            AppLogger.Log($"[HotReload] {w}");

                    _onChanged(newCfg);
                    AppLogger.Log($"[HotReload] Konfiguraatio ladattu uudelleen: {e.FullPath}");
                }
                catch (Exception ex)
                {
                    AppLogger.Log($"[HotReload] Latausvirhe: {ex.Message}");
                }
            });
        }

        public void Dispose()
        {
            try
            {
                if (_fsw != null)
                {
                    _fsw.EnableRaisingEvents = false;
                    _fsw.Changed -= OnFileChanged;
                    _fsw.Dispose();
                }
            }
            catch { }
        }
    }
}
