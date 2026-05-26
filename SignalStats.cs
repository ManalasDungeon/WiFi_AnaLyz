using System;
using System.Collections.Generic;

namespace WifiAnalyzerPro
{
    // ═══════════════════════════════════════════════════════════
    // SIGNAALITILASTO — ring buffer + Welford online-algoritmi
    // ═══════════════════════════════════════════════════════════

    public class SignalStats
    {
        // Ring buffer — korvaa Queue<SignalPoint> per AP
        private readonly int[]      _rssiRing;
        private readonly DateTime[] _timeRing;
        private int _head;
        private int _count;
        private readonly int _capacity;

        // Welford online-algoritmi → varianssi/jitter O(1)
        private int    _n;
        private double _mean;
        private double _M2;

        // EMA-pari → trendi O(1)
        private double _emaFast = double.NaN;
        private double _emaSlow = double.NaN;

        private const double AlphaFast = 0.25;
        private const double AlphaSlow = 0.04;

        public SignalStats(int capacity = 120)
        {
            _capacity = capacity;
            _rssiRing = new int[capacity];
            _timeRing = new DateTime[capacity];
        }

        // O(1) — kutsutaan joka kerta kun uusi RSSI-piste saapuu
        public void AddPoint(int rssi, DateTime time)
        {
            _dirty = true;
            _rssiRing[_head] = rssi;
            _timeRing[_head] = time;
            _head = (_head + 1) % _capacity;
            if (_count < _capacity) _count++;

            // Welford
            _n++;
            double delta = rssi - _mean;
            _mean += delta / _n;
            _M2   += delta * (rssi - _mean);

            // EMA
            if (double.IsNaN(_emaFast)) { _emaFast = rssi; _emaSlow = rssi; }
            else
            {
                _emaFast = AlphaFast * rssi + (1 - AlphaFast) * _emaFast;
                _emaSlow = AlphaSlow * rssi + (1 - AlphaSlow) * _emaSlow;
            }
        }

        // Palauttaa pisteet aikajärjestyksessä (vanhin ensin) kaaviopiirtoa varten
        public SignalPoint[] GetHistory()
        {
            var result = new SignalPoint[_count];
            int start  = _count < _capacity ? 0 : _head;
            for (int i = 0; i < _count; i++)
            {
                int idx = (start + i) % _capacity;
                result[i] = new SignalPoint { Time = _timeRing[idx], Rssi = _rssiRing[idx] };
            }
            return result;
        }

        // Lataa historia JSON:sta käynnistyksen yhteydessä
        public void SeedFromHistory(IEnumerable<SignalPoint> points)
        {
            foreach (var p in points) AddPoint(p.Rssi, p.Time);
        }

        // Dirty-lippu BuildHistorySnapshot()-optimointia varten
        private bool _dirty = true;
        public bool IsDirty => _dirty;
        public void MarkClean() => _dirty = false;

        public double Jitter => _n < 5 ? 0.0 : Math.Round(Math.Sqrt(_M2 / _n), 1);
        public double Trend  => (!double.IsNaN(_emaFast) && !double.IsNaN(_emaSlow) && _n >= 10)
            ? Math.Round(_emaFast - _emaSlow, 1) : 0.0;
        public int Count => _count;

        public void Reset()
        {
            _head = 0; _count = 0; _n = 0;
            _mean = 0.0; _M2 = 0.0;
            _emaFast = double.NaN; _emaSlow = double.NaN;
            _dirty = true; // pakota historia-välimuistin uusiminen seuraavalla kierroksella
        }
    }
}
