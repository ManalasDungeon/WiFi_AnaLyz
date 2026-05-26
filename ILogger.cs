using System;
using System.IO;

namespace WifiAnalyzerPro
{
    public interface IWifiLogger
    {
        void Log(string message);
    }

    /// <summary>Kirjoittaa System.Diagnostics.Debug-kanavaan (kehitysympäristö).</summary>
    public sealed class DebugLogger : IWifiLogger
    {
        public void Log(string message) => System.Diagnostics.Debug.WriteLine(message);
    }

    /// <summary>Kirjoittaa aikaleimalla append-only-lokitiedostoon.</summary>
    public sealed class FileLogger : IWifiLogger
    {
        private readonly string _path;
        private readonly object _lock = new();

        public FileLogger(string path) => _path = path;

        public void Log(string message)
        {
            try
            {
                lock (_lock)
                    File.AppendAllText(_path,
                        $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {message}\r\n",
                        System.Text.Encoding.UTF8);
            }
            catch { }
        }
    }

    /// <summary>Staattinen lokittaja — konfiguroidaan kerran käynnistyksen yhteydessä.</summary>
    public static class AppLogger
    {
        private static IWifiLogger _logger = new DebugLogger();

        public static void Configure(IWifiLogger logger) => _logger = logger ?? new DebugLogger();
        public static void Log(string message) => _logger.Log(message);
    }
}
