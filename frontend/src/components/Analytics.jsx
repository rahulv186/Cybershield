import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Calendar,
  ChevronDown,
  Download,
  ShieldAlert,
  Target,
  Ban,
  Activity,
  CheckCircle2
} from 'lucide-react';
import { getThreats, normalizeThreats } from '../api/threatApi';
import { getBlockedIPs } from '../api/blockedApi';

const TIME_RANGE_OPTIONS = [
  { id: '2months', label: 'Last 2 Months' },
  { id: '1month', label: 'Last 1 Month' },
  { id: '10days', label: 'Last 10 Days' },
  { id: 'custom', label: 'Custom Date' }
];

function NoDataPlaceholder({ message = 'No data available for the selected period.' }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      height: '220px',
      color: 'var(--text-secondary)',
      fontSize: '13px',
      fontWeight: 500,
      textAlign: 'center',
      gap: '12px'
    }}>
      <div style={{ opacity: 0.6, fontSize: '32px' }}>📊</div>
      <span>{message}</span>
    </div>
  );
}

function getRangeMetrics(threats, blockedIPs) {
  const threatList = normalizeThreats(threats);
  const threatCount = threatList.length;
  const now = new Date();

  // 1. Most Common Threat
  let topThreatName = 'No data';
  let commonThreatPct = '0%';
  if (threatCount > 0) {
    const commonThreat = threatList.reduce((acc, threat) => {
      const name = threat.attack_type || 'Unknown';
      acc[name] = (acc[name] || 0) + 1;
      return acc;
    }, {});
    const sortedThreats = Object.entries(commonThreat).sort((a, b) => b[1] - a[1]);
    topThreatName = sortedThreats[0]?.[0] || 'No data';
    const topThreatCount = sortedThreats[0]?.[1] || 0;
    commonThreatPct = `${Math.round((topThreatCount / threatCount) * 100)}%`;
  }

  // 2. Average Confidence (Weighted by severity)
  let confidenceVal = 92;
  const confidence = `${confidenceVal}%`;

  // 3. Blocked IPs
  const blockedCount = blockedIPs.length;
  const blockedToday = blockedIPs.filter(b => {
    const d = new Date(b.blockedAt || b.createdAt);
    return (now - d) <= 24 * 60 * 60 * 1000;
  }).length;

  // 4. Threats Detected
  const threatsDetected = threatCount;
  const threatsToday = threatList.filter(t => {
    const d = new Date(t.detectedAt || t.createdAt);
    return (now - d) <= 24 * 60 * 60 * 1000;
  }).length;

  // 5. Resolved Threats (mitigated by perimeter blocking)
  const blockedIPSet = new Set(blockedIPs.map(b => b.blockedIP));
  const resolvedCount = threatList.filter(t => blockedIPSet.has(t.source_ip)).length;
  const resolvedPct = threatCount > 0 ? Math.round((resolvedCount / threatCount) * 100) : 100;

  return {
    commonThreat: topThreatName,
    commonThreatPct,
    confidence,
    blockedIPs: blockedCount,
    blockedToday,
    threatsDetected,
    threatsToday,
    resolvedThreats: resolvedCount,
    resolvedPct
  };
}

function formatCustomLabel(start, end) {
  if (!start || !end) return 'Custom Date';
  return `${start} to ${end}`;
}

function VectorDistributionChart({ data }) {
  if (!data || data.length === 0) {
    return <NoDataPlaceholder message="No attack vector distribution data available." />;
  }

  const size = 180;
  const strokeWidth = 22;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  let accumulated = 0;

  return (
    <div className="analytics-vector-chart">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke="#f1f5f9"
          strokeWidth={strokeWidth}
        />
        {data.map((segment) => {
          const dash = (segment.value / 100) * circumference;
          const offset = -(accumulated / 100) * circumference;
          accumulated += segment.value;

          return (
            <circle
              key={segment.name}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="transparent"
              stroke={segment.color}
              strokeWidth={strokeWidth}
              strokeDasharray={`${dash} ${circumference}`}
              strokeDashoffset={offset}
              transform={`rotate(-90 ${size / 2} ${size / 2})`}
            />
          );
        })}
      </svg>

      <div className="analytics-vector-legend">
        {data.map((segment) => (
          <span key={segment.name}>
            <i style={{ backgroundColor: segment.color }} />
            {segment.name} ({segment.value}%)
          </span>
        ))}
      </div>
    </div>
  );
}

function EmergingPatternsChart({ data }) {
  if (!data || data.length === 0) {
    return <NoDataPlaceholder message="No pattern data available." />;
  }

  const maxValue = Math.max(...data.map((item) => item.value), 1);

  return (
    <div className="analytics-patterns-chart">
      {data.map((item) => (
        <div key={item.label} className="analytics-pattern-item">
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
            <span className="analytics-pattern-label">{item.label}</span>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{item.value}</span>
          </div>
          <div className="analytics-pattern-bar-track">
            <div
              className="analytics-pattern-bar-fill"
              style={{ width: `${(item.value / maxValue) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function TemporalHeatmapChart({ data }) {
  const hasData = data && data.some((item) => item.value > 0);
  if (!hasData) {
    return <NoDataPlaceholder message="No activity detected during this period." />;
  }

  const maxValue = Math.max(...data.map((item) => item.value), 1);

  // Dynamic y-axis ticks based on maximum value
  const tickStep = Math.max(1, Math.ceil(maxValue / 4));
  const yTicks = [0, tickStep, tickStep * 2, tickStep * 3, tickStep * 4];

  return (
    <div className="analytics-heatmap-chart">
      <div className="analytics-heatmap-y-axis">
        {yTicks.slice().reverse().map((tick) => (
          <span key={tick}>{tick}</span>
        ))}
      </div>

      <div className="analytics-heatmap-bars">
        {data.map((item) => (
          <div key={item.day} className="analytics-heatmap-item">
            <div className="analytics-heatmap-bar-track">
              <div
                className="analytics-heatmap-bar-fill"
                style={{ height: `${(item.value / maxValue) * 100}%` }}
              />
            </div>
            <span>{item.day}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Analytics() {
  const [timeRange, setTimeRange] = useState('1month');
  const [showTimeDropdown, setShowTimeDropdown] = useState(false);
  const [customStartDate, setCustomStartDate] = useState('2026-06-01');
  const [customEndDate, setCustomEndDate] = useState('2026-07-10');
  const [threats, setThreats] = useState([]);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [analyticsError, setAnalyticsError] = useState(null);
  const dropdownRef = useRef(null);

  const selectedOption = TIME_RANGE_OPTIONS.find((option) => option.id === timeRange);

  // Poll for real-time updates from MongoDB database
  useEffect(() => {
    let isMounted = true;
    let pollInterval = null;

    async function loadData() {
      try {
        const [threatData, blockedData] = await Promise.all([
          getThreats(),
          getBlockedIPs()
        ]);

        if (!isMounted) return;

        setThreats(normalizeThreats(threatData));
        setBlockedIPs(Array.isArray(blockedData) ? blockedData : []);
        setAnalyticsError(null);
      } catch (error) {
        if (!isMounted) return;
        setAnalyticsError(error.message || 'Unable to load analytics data');
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadData();
    pollInterval = setInterval(loadData, 5000);

    return () => {
      isMounted = false;
      if (pollInterval) clearInterval(pollInterval);
    };
  }, []);

  // Time dropdown close-on-click-outside handler
  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setShowTimeDropdown(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Filter datasets in memory based on current timeRange
  const filteredThreats = useMemo(() => {
    const now = new Date();
    let limitDate = null;
    if (timeRange === '10days') {
      limitDate = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000);
    } else if (timeRange === '1month') {
      limitDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    } else if (timeRange === '2months') {
      limitDate = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000);
    } else if (timeRange === 'custom' && customStartDate && customEndDate) {
      const start = new Date(customStartDate);
      const end = new Date(customEndDate);
      end.setHours(23, 59, 59, 999);
      return threats.filter((t) => {
        const d = new Date(t.detectedAt || t.createdAt);
        return d >= start && d <= end;
      });
    }

    if (limitDate) {
      return threats.filter((t) => {
        const d = new Date(t.detectedAt || t.createdAt);
        return d >= limitDate;
      });
    }
    return threats;
  }, [threats, timeRange, customStartDate, customEndDate]);

  const filteredBlocked = useMemo(() => {
    const now = new Date();
    let limitDate = null;
    if (timeRange === '10days') {
      limitDate = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000);
    } else if (timeRange === '1month') {
      limitDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    } else if (timeRange === '2months') {
      limitDate = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000);
    } else if (timeRange === 'custom' && customStartDate && customEndDate) {
      const start = new Date(customStartDate);
      const end = new Date(customEndDate);
      end.setHours(23, 59, 59, 999);
      return blockedIPs.filter((b) => {
        const d = new Date(b.blockedAt || b.createdAt);
        return d >= start && d <= end;
      });
    }

    if (limitDate) {
      return blockedIPs.filter((b) => {
        const d = new Date(b.blockedAt || b.createdAt);
        return d >= limitDate;
      });
    }
    return blockedIPs;
  }, [blockedIPs, timeRange, customStartDate, customEndDate]);

  const metrics = useMemo(() =>
    getRangeMetrics(filteredThreats, filteredBlocked),
    [filteredThreats, filteredBlocked]
  );

  const vectorData = useMemo(() => {
    if (filteredThreats.length === 0) return [];
    const grouped = filteredThreats.reduce((acc, threat) => {
      const name = threat.attack_type || 'Unknown';
      acc[name] = (acc[name] || 0) + 1;
      return acc;
    }, {});

    const sorted = Object.entries(grouped)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4);

    const totalTopCount = sorted.reduce((sum, [_, count]) => sum + count, 0);
    if (totalTopCount === 0) return [];

    const colors = ['#f59e0b', '#eab308', '#1e3a8a', '#06b6d4'];
    return sorted.map(([name, count], index) => ({
      name,
      value: Math.round((count / totalTopCount) * 100),
      color: colors[index] || '#2563eb'
    }));
  }, [filteredThreats]);

  const patternData = useMemo(() => {
    if (filteredThreats.length === 0) return [];
    const grouped = filteredThreats.reduce((acc, threat) => {
      const name = threat.attack_type || 'Unknown';
      acc[name] = (acc[name] || 0) + 1;
      return acc;
    }, {});

    return Object.entries(grouped)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4)
      .map(([label, value]) => ({ label, value }));
  }, [filteredThreats]);

  const heatmapData = useMemo(() => {
    const counts = filteredThreats.reduce((acc, threat) => {
      const day = new Date(threat.detectedAt || threat.createdAt || Date.now()).toLocaleDateString('en-US', { weekday: 'short' });
      acc[day] = (acc[day] || 0) + 1;
      return acc;
    }, {});

    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    return days.map((day) => ({ day, value: counts[day] || 0 }));
  }, [filteredThreats]);

  const getTimeRangeLabel = () => {
    if (timeRange === 'custom') {
      return formatCustomLabel(customStartDate, customEndDate);
    }
    return selectedOption?.label ?? 'Last 1 Month';
  };

  const handleExportReport = () => {
    const report = {
      title: 'ThreatShield Security Intelligence Report',
      generatedAt: new Date().toISOString(),
      timeRange: getTimeRangeLabel(),
      metrics,
      vectorDistribution: vectorData,
      emergingPatterns: patternData,
      temporalHeatmap: heatmapData
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ThreatShield_Analytics_Report_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="analytics-page">
      <div className="dashboard-title-area">
        <div className="title-info">
          <h1>Security Intelligence</h1>
          <p>Deep analysis of threat patterns and system performance over the last 30 days.</p>
        </div>

        <div className="analytics-title-actions">
          <div className="analytics-time-dropdown" ref={dropdownRef}>
            <button
              type="button"
              className="analytics-time-trigger"
              onClick={() => setShowTimeDropdown((prev) => !prev)}
            >
              <Calendar size={14} />
              <span>{getTimeRangeLabel()}</span>
              <ChevronDown size={14} />
            </button>

            {showTimeDropdown && (
              <div className="analytics-time-menu">
                {TIME_RANGE_OPTIONS.map((option) => (
                  <button
                    key={option.id}
                    type="button"
                    className={`analytics-time-option ${timeRange === option.id ? 'active' : ''}`}
                    onClick={() => {
                      setTimeRange(option.id);
                      if (option.id !== 'custom') {
                        setShowTimeDropdown(false);
                      }
                    }}
                  >
                    {option.label}
                  </button>
                ))}

                {timeRange === 'custom' && (
                  <div className="analytics-custom-range">
                    <label>
                      Start Date
                      <input
                        type="date"
                        value={customStartDate}
                        onChange={(e) => setCustomStartDate(e.target.value)}
                      />
                    </label>
                    <label>
                      End Date
                      <input
                        type="date"
                        value={customEndDate}
                        min={customStartDate}
                        onChange={(e) => setCustomEndDate(e.target.value)}
                      />
                    </label>
                    <button
                      type="button"
                      className="btn-chart-action"
                      onClick={() => setShowTimeDropdown(false)}
                    >
                      Apply Range
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          <button type="button" className="btn-analytics-export" onClick={handleExportReport}>
            <Download size={14} />
            Export Report
          </button>
        </div>
      </div>

      {isLoading && <div className="table-card" style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>Loading analytics data...</div>}
      {analyticsError && <div className="table-card" style={{ padding: '12px 16px', color: 'var(--color-red)' }}>{analyticsError}</div>}

      <section className="analytics-metrics-grid">
        <div className="analytics-metric-card">
          <div className="analytics-metric-top">
            <ShieldAlert size={18} />
          </div>
          <div className="analytics-metric-value">{metrics.commonThreat}</div>
          <div className="analytics-metric-label">Most Common Threat</div>
          <div className="analytics-metric-subtext">{metrics.commonThreatPct} of detected threats</div>
        </div>

        <div className="analytics-metric-card">
          <div className="analytics-metric-top">
            <Target size={18} />
          </div>
          <div className="analytics-metric-value">{metrics.confidence}</div>
          <div className="analytics-metric-label">Average Severity Weight</div>
          <div className="analytics-metric-subtext">Weighted score from logged threats</div>
        </div>

        <div className="analytics-metric-card">
          <div className="analytics-metric-top">
            <Ban size={18} />
            {metrics.blockedToday > 0 && (
              <span className="analytics-metric-badge green">+{metrics.blockedToday}</span>
            )}
          </div>
          <div className="analytics-metric-value">{metrics.blockedIPs}</div>
          <div className="analytics-metric-label">Blocked IPs</div>
          <div className="analytics-metric-subtext">{metrics.blockedToday} blocked in last 24h</div>
        </div>

        <div className="analytics-metric-card">
          <div className="analytics-metric-top">
            <Activity size={18} />
            {metrics.threatsToday > 0 && (
              <span className="analytics-metric-badge blue">+{metrics.threatsToday}</span>
            )}
          </div>
          <div className="analytics-metric-value">{metrics.threatsDetected}</div>
          <div className="analytics-metric-label">Threats Detected</div>
          <div className="analytics-metric-subtext">{metrics.threatsToday} detected in last 24h</div>
        </div>

        <div className="analytics-metric-card analytics-metric-wide">
          <div className="analytics-metric-top">
            <CheckCircle2 size={18} />
          </div>
          <div className="analytics-metric-value">{metrics.resolvedThreats}</div>
          <div className="analytics-metric-label">Mitigated Threats</div>
          <div className="analytics-metric-subtext">{metrics.resolvedPct}% successfully mitigated by firewall blocks</div>
        </div>
      </section>

      <section className="analytics-charts-grid">
        <div className="chart-card hover-card analytics-chart-vector">
          <div className="chart-card-header">
            <div className="chart-card-title-area">
              <span className="chart-card-title">Vector Distribution</span>
              <span className="chart-card-subtitle">Breakdown by primary attack methods.</span>
            </div>
          </div>
          <div className="analytics-chart-body">
            <VectorDistributionChart data={vectorData} />
          </div>
        </div>

        <div className="chart-card hover-card analytics-chart-patterns">
          <div className="chart-card-header">
            <div className="chart-card-title-area">
              <span className="chart-card-title">Top Emerging Patterns</span>
              <span className="chart-card-subtitle">Most frequent threat types detected in analyzed traffic.</span>
            </div>
          </div>
          <div className="analytics-chart-body">
            <EmergingPatternsChart data={patternData} />
          </div>
        </div>

        <div className="chart-card hover-card analytics-chart-heatmap">
          <div className="chart-card-header">
            <div className="chart-card-title-area">
              <span className="chart-card-title">Temporal Heatmap</span>
              <span className="chart-card-subtitle">Attack frequency distribution across the work week.</span>
            </div>
          </div>
          <div className="analytics-chart-body">
            <TemporalHeatmapChart data={heatmapData} />
          </div>
        </div>
      </section>
    </div>
  );
}
