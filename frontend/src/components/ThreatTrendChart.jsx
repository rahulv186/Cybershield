import React, { useEffect, useState, useRef, useMemo } from 'react';
import { getThreats } from '../api/threatApi';

export default function ThreatTrendChart() {
  const [viewType, setViewType] = useState('24h');
  const [hoveredPoint, setHoveredPoint] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const [trendData, setTrendData] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isLive, setIsLive] = useState(true);
  const containerRef = useRef(null);
  const prevDataLengthRef = useRef(0);

  useEffect(() => {
    let isMounted = true;
    let pollInterval;

    async function loadTrendData() {
      try {
        setIsLoading(true);
        const threats = await getThreats();
        if (!isMounted) return;

        const threatList = Array.isArray(threats) ? threats : [];
        
        // Group by timestamp and count threats
        const grouped = threatList.reduce((acc, threat) => {
          const key = threat.detectedAt || 'Unknown';
          acc[key] = (acc[key] || 0) + 1;
          return acc;
        }, {});

        const mapped = Object.entries(grouped)
          .map(([label, value]) => ({ label, value }))
          .sort((a, b) => new Date(a.label) - new Date(b.label));

        // Keep only the latest 75 points for live monitoring
        const trimmedData = mapped.slice(-75);
        
        setTrendData(trimmedData.length > 0 ? trimmedData : []);
        setError(null);
      } catch (err) {
        if (!isMounted) return;
        setError(err.message || 'Unable to load trend data');
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadTrendData();

    // Poll every 5 seconds (keeping existing polling mechanism)
    pollInterval = setInterval(loadTrendData, 5000);

    return () => {
      isMounted = false;
      clearInterval(pollInterval);
    };
  }, []);

  // Calculate dynamic Y-axis scaling
  const { maxVal, yTicks, latestThreatCount, peakThreatCount } = useMemo(() => {
    if (trendData.length === 0) {
      return { maxVal: 10, yTicks: [0, 2, 4, 6, 8, 10], latestThreatCount: 0, peakThreatCount: 0 };
    }

    const values = trendData.map(d => d.value);
    const max = Math.max(...values);
    const latest = values[values.length - 1];
    const peak = max;

    // Add 10-20% padding above the highest value
    const padding = max === 0 ? 10 : Math.max(10, Math.ceil(max * 0.15));
    const scaledMax = max + padding;

    // Generate nice round numbers for Y-axis ticks
    const tickCount = 5;
    const tickStep = Math.ceil(scaledMax / tickCount / 5) * 5; // Round to nearest 5
    const niceMax = tickStep * tickCount;
    
    const ticks = [];
    for (let i = 0; i <= tickCount; i++) {
      ticks.push(i * tickStep);
    }

    return {
      maxVal: niceMax,
      yTicks: ticks,
      latestThreatCount: latest,
      peakThreatCount: peak
    };
  }, [trendData]);

  // Chart configuration
  const width = 800;
  const height = 280;
  const paddingLeft = 50;
  const paddingRight = 20;
  const paddingTop = 25;
  const paddingBottom = 35;

  const chartWidth = width - paddingLeft - paddingRight;
  const chartHeight = height - paddingTop - paddingBottom;

  // Map values to coordinates
  const points = useMemo(() => {
    return trendData.map((d, index) => {
      const x = trendData.length === 1
        ? paddingLeft + chartWidth / 2
        : paddingLeft + (index * chartWidth) / (trendData.length - 1);
      
      const clampedValue = Math.min(d.value, maxVal);
      const y = paddingTop + chartHeight - (clampedValue / maxVal) * chartHeight;
      
      return { x, y, value: d.value, label: d.label, original: d };
    });
  }, [trendData, maxVal, chartWidth, chartHeight, paddingLeft, paddingTop]);

  // Calculate smooth Bezier path
  const getBezierPath = (pts) => {
    if (pts.length === 0) return '';
    if (pts.length === 1) {
      // Single point - draw a small circle
      return `M ${pts[0].x} ${pts[0].y} L ${pts[0].x} ${pts[0].y}`;
    }
    
    let d = `M ${pts[0].x} ${pts[0].y}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[i];
      const p1 = pts[i + 1];
      const cpX1 = p0.x + (p1.x - p0.x) / 3;
      const cpY1 = p0.y;
      const cpX2 = p0.x + (2 * (p1.x - p0.x)) / 3;
      const cpY2 = p1.y;
      d += ` C ${cpX1} ${cpY1}, ${cpX2} ${cpY2}, ${p1.x} ${p1.y}`;
    }
    return d;
  };

  const linePath = getBezierPath(points);
  
  // Area path closure
  const areaPath = points.length > 0 
    ? `${linePath} L ${points[points.length - 1].x} ${height - paddingBottom} L ${points[0].x} ${height - paddingBottom} Z`
    : '';

  // Handle Mouse Hover Interactions
  const handleMouseMove = (e) => {
    if (!containerRef.current || points.length === 0) return;
    const rect = containerRef.current.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;

    // Convert mouseX to SVG coordinate space
    const svgMouseX = (mouseX / rect.width) * width;
    
    // Find closest point by x coordinate
    let closest = points[0];
    let minDiff = Math.abs(points[0].x - svgMouseX);

    for (let i = 1; i < points.length; i++) {
      const diff = Math.abs(points[i].x - svgMouseX);
      if (diff < minDiff) {
        minDiff = diff;
        closest = points[i];
      }
    }

    setHoveredPoint(closest);
    // Place tooltip relative to closest point, converting back to DOM coordinates
    const tooltipDOMX = (closest.x / width) * rect.width;
    const tooltipDOMY = (closest.y / height) * rect.height;
    
    setTooltipPos({ 
      x: tooltipDOMX, 
      y: tooltipDOMY - 50 
    });
  };

  const handleMouseLeave = () => {
    setHoveredPoint(null);
  };

  // Format timestamp for display
  const formatTimestamp = (timestamp) => {
    try {
      const date = new Date(timestamp);
      if (viewType === '24h') {
        return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
      }
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    } catch {
      return timestamp;
    }
  };

  // Check if there's no threat data
  const hasNoThreats = trendData.length === 0 || trendData.every(d => d.value === 0);

  return (
    <div className="chart-card hover-card">
      <div className="chart-card-header">
        <div className="chart-card-title-area">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className="chart-card-title">Threat Trend</span>
            {isLive && (
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '6px',
                padding: '3px 8px',
                background: 'rgba(34, 197, 94, 0.1)',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                borderRadius: '9999px',
                fontSize: '10px',
                fontWeight: 600,
                color: '#22c55e',
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}>
                <span style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  background: '#22c55e',
                  animation: 'pulse 2s ease-in-out infinite'
                }}></span>
                Live
              </div>
            )}
          </div>
          <span className="chart-card-subtitle">
            Attack volume detected over the last {viewType === '24h' ? '24 hours' : '7 days'}.
          </span>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <div style={{ 
            display: 'flex', 
            gap: '16px', 
            marginRight: '12px',
            fontSize: '11px',
            color: 'var(--text-secondary)'
          }}>
            <div>
              <span style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>Latest: </span>
              <span style={{ color: 'var(--color-blue)', fontWeight: 600 }}>{latestThreatCount}</span>
            </div>
            <div>
              <span style={{ color: 'var(--text-secondary)', fontSize: '10px' }}>Peak: </span>
              <span style={{ color: 'var(--color-orange)', fontWeight: 600 }}>{peakThreatCount}</span>
            </div>
          </div>
          <button 
            className="btn-chart-action"
            onClick={() => setViewType(viewType === '24h' ? '7d' : '24h')}
          >
            {viewType === '24h' ? '7 Days' : '24 Hours'}
          </button>
        </div>
      </div>

      <div 
        className="svg-chart-container" 
        ref={containerRef}
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
      >
        {isLoading ? (
          <div style={{ minHeight: '280px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
            Loading trend data...
          </div>
        ) : error ? (
          <div style={{ minHeight: '280px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--color-red)' }}>
            {error}
          </div>
        ) : hasNoThreats ? (
          <div style={{ 
            minHeight: '280px', 
            display: 'flex', 
            flexDirection: 'column',
            alignItems: 'center', 
            justifyContent: 'center', 
            color: 'var(--text-secondary)',
            gap: '12px'
          }}>
            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3">
              <path d="M3 12h4l3-9 4 18 3-9h4" />
            </svg>
            <span style={{ fontSize: '13px', fontWeight: 500 }}>No threats detected in the selected time window</span>
          </div>
        ) : (
          <svg viewBox={`0 0 ${width} ${height}`} className="chart-svg" style={{ animation: 'fadeIn 0.5s ease-in' }}>
            <defs>
              <linearGradient id="chartGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3B82F6" stopOpacity="0.25" />
                <stop offset="100%" stopColor="#3B82F6" stopOpacity="0.02" />
              </linearGradient>
              <filter id="glow">
                <feGaussianBlur stdDeviation="2.5" result="coloredBlur"/>
                <feMerge>
                  <feMergeNode in="coloredBlur"/>
                  <feMergeNode in="SourceGraphic"/>
                </feMerge>
              </filter>
            </defs>

            {/* Grid lines */}
            {yTicks.map((tick, idx) => {
              const y = paddingTop + chartHeight - (tick / maxVal) * chartHeight;
              return (
                <g key={idx}>
                  <line 
                    x1={paddingLeft} 
                    y1={y} 
                    x2={width - paddingRight} 
                    y2={y} 
                    stroke="rgba(255,255,255,0.08)" 
                    strokeWidth="1"
                  />
                  <text 
                    x={paddingLeft - 10} 
                    y={y + 3} 
                    textAnchor="end" 
                    fill="var(--text-secondary)"
                    fontSize="10px"
                    fontFamily="var(--font-sans)"
                  >
                    {tick}
                  </text>
                </g>
              );
            })}

            {/* Area fill */}
            {areaPath && (
              <path 
                d={areaPath} 
                fill="url(#chartGradient)" 
                style={{ 
                  animation: 'fadeIn 0.8s ease-in',
                  transition: 'd 0.5s ease-in-out'
                }}
              />
            )}

            {/* Trend Line */}
            {linePath && points.length > 1 && (
              <path 
                d={linePath} 
                fill="none" 
                stroke="#3B82F6" 
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                filter="url(#glow)"
                style={{ 
                  animation: 'drawLine 1s ease-out',
                  transition: 'd 0.5s ease-in-out'
                }}
              />
            )}

            {/* Peak markers */}
            {points.map((pt, idx) => {
              const isPeak = pt.value === peakThreatCount && pt.value > 0;
              const isLatest = idx === points.length - 1;
              
              if (!isPeak && !isLatest) return null;

              return (
                <g key={`peak-${idx}`}>
                  {isPeak && (
                    <>
                      <circle
                        cx={pt.x}
                        cy={pt.y}
                        r="6"
                        fill="#60A5FA"
                        stroke="#0F172A"
                        strokeWidth="2"
                        style={{ animation: 'scaleIn 0.3s ease-out' }}
                      />
                      <text
                        x={pt.x}
                        y={pt.y - 12}
                        textAnchor="middle"
                        fill="#60A5FA"
                        fontSize="10px"
                        fontWeight="600"
                        fontFamily="var(--font-sans)"
                      >
                        {pt.value}
                      </text>
                    </>
                  )}
                  {isLatest && !isPeak && (
                    <circle
                      cx={pt.x}
                      cy={pt.y}
                      r="4"
                      fill="#3B82F6"
                      stroke="#ffffff"
                      strokeWidth="2"
                      style={{ animation: 'pulse 2s ease-in-out infinite' }}
                    />
                  )}
                </g>
              );
            })}

            {/* X Axis Labels - Show every nth label based on data length */}
            {points.map((pt, idx) => {
              // Show approximately 6-8 labels
              const step = Math.ceil(points.length / 7);
              if (idx % step !== 0 && idx !== points.length - 1) return null;

              return (
                <text
                  key={idx}
                  x={pt.x}
                  y={height - 12}
                  textAnchor="middle"
                  fill="var(--text-secondary)"
                  fontSize="10px"
                  fontFamily="var(--font-sans)"
                >
                  {formatTimestamp(pt.label)}
                </text>
              );
            })}

            {/* Hover interactive helpers */}
            {hoveredPoint && (
              <g style={{ animation: 'fadeIn 0.15s ease-in' }}>
                {/* Vertical dotted track line */}
                <line
                  x1={hoveredPoint.x}
                  y1={paddingTop}
                  x2={hoveredPoint.x}
                  y2={height - paddingBottom}
                  stroke="#3B82F6"
                  strokeWidth="1"
                  strokeDasharray="3,3"
                  opacity="0.5"
                />
                {/* Horizontal line to Y-axis */}
                <line
                  x1={paddingLeft}
                  y1={hoveredPoint.y}
                  x2={hoveredPoint.x}
                  y2={hoveredPoint.y}
                  stroke="#3B82F6"
                  strokeWidth="1"
                  strokeDasharray="3,3"
                  opacity="0.5"
                />
                {/* Pulsing indicator node */}
                <circle
                  cx={hoveredPoint.x}
                  cy={hoveredPoint.y}
                  r="8"
                  fill="#3B82F6"
                  opacity="0.2"
                  style={{ animation: 'pulse 1.5s ease-in-out infinite' }}
                />
                <circle
                  cx={hoveredPoint.x}
                  cy={hoveredPoint.y}
                  r="5"
                  fill="#3B82F6"
                  stroke="#ffffff"
                  strokeWidth="2"
                />
              </g>
            )}
          </svg>
        )}

        {/* Floating Tooltip HTML Overlay */}
        {hoveredPoint && !hasNoThreats && (
          <div 
            className="chart-tooltip"
            style={{ 
              left: `${tooltipPos.x}px`, 
              top: `${tooltipPos.y}px`,
              transform: 'translateX(-50%)',
              animation: 'fadeIn 0.15s ease-in'
            }}
          >
            <span className="chart-tooltip-time">{formatTimestamp(hoveredPoint.label)}</span>
            <span className="chart-tooltip-value">{hoveredPoint.value.toLocaleString()} {hoveredPoint.value === 1 ? 'threat' : 'threats'}</span>
          </div>
        )}
      </div>

      <style jsx>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        
        @keyframes scaleIn {
          from { transform: scale(0); opacity: 0; }
          to { transform: scale(1); opacity: 1; }
        }
        
        @keyframes drawLine {
          from { stroke-dashoffset: 1000; }
          to { stroke-dashoffset: 0; }
        }
      `}</style>
    </div>
  );
}