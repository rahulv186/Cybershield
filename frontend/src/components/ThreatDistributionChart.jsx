import React, { useEffect, useState } from 'react';
import { getThreats } from '../api/threatApi';

export default function ThreatDistributionChart() {
  const [categories, setCategories] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeCategory, setActiveCategory] = useState(null);

  useEffect(() => {
    let isMounted = true;

    async function loadDistribution() {
      try {
        setIsLoading(true);
        const threats = await getThreats();
        if (!isMounted) return;

        const threatList = Array.isArray(threats) ? threats : [];
        const grouped = threatList.reduce((acc, threat) => {
          const key = threat.attack_type || 'Unknown';
          acc[key] = (acc[key] || 0) + 1;
          return acc;
        }, {});

        const nextCategories = Object.entries(grouped).slice(0, 5).map(([name, count], index) => ({
          name,
          value: Math.max(5, Math.round((count / Math.max(1, threatList.length)) * 100)),
          color: ['#2563eb', '#06b6d4', '#1e293b', '#f59e0b', '#fb923c'][index] || '#2563eb',
          label: `${name} (${Math.max(5, Math.round((count / Math.max(1, threats.length)) * 100))}%)`
        }));

        setCategories(nextCategories);
        setError(null);
      } catch (err) {
        if (!isMounted) return;
        setError(err.message || 'Unable to load distribution');
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadDistribution();
    return () => { isMounted = false; };
  }, []);

  const size = 160;
  const strokeWidth = 20;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  let accumulatedPercent = 0;
  const displayCategory = activeCategory || categories[0];

  if (isLoading) {
    return (
      <div className="chart-card hover-card">
        <div className="chart-card-header">
          <div className="chart-card-title-area">
            <span className="chart-card-title">Threat Distribution</span>
            <span className="chart-card-subtitle">Detection breakdown by category.</span>
          </div>
        </div>
        <div className="donut-container" style={{ minHeight: '220px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
          Loading distribution...
        </div>
      </div>
    );
  }

  if (error || categories.length === 0) {
    return (
      <div className="chart-card hover-card">
        <div className="chart-card-header">
          <div className="chart-card-title-area">
            <span className="chart-card-title">Threat Distribution</span>
            <span className="chart-card-subtitle">Detection breakdown by category.</span>
          </div>
        </div>
        <div className="donut-container" style={{ minHeight: '220px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
          TODO: Backend endpoint required for threat distribution data.
        </div>
      </div>
    );
  }

  return (
    <div className="chart-card hover-card">
      <div className="chart-card-header">
        <div className="chart-card-title-area">
          <span className="chart-card-title">Threat Distribution</span>
          <span className="chart-card-subtitle">Detection breakdown by category.</span>
        </div>
      </div>

      <div className="donut-container">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="donut-svg">
          <circle 
            cx={size / 2} 
            cy={size / 2} 
            r={radius} 
            fill="transparent" 
            stroke="var(--bg-tertiary)" 
            strokeWidth={strokeWidth} 
          />
          
          {categories.map((cat, idx) => {
            const strokeDashValue = (cat.value / 100) * circumference;
            const strokeDashOffset = -(accumulatedPercent / 100) * circumference;
            accumulatedPercent += cat.value;

            const isHovered = activeCategory?.name === cat.name;

            return (
              <circle
                key={idx}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="transparent"
                stroke={cat.color}
                strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                strokeDasharray={`${strokeDashValue} ${circumference}`}
                strokeDashoffset={strokeDashOffset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
                className="donut-segment"
                onMouseEnter={() => setActiveCategory(cat)}
                onMouseLeave={() => setActiveCategory(null)}
              />
            );
          })}
        </svg>

        <div className="donut-center-text">
          <span className="donut-center-label">{displayCategory.name}</span>
          <span className="donut-center-val" style={{ color: displayCategory.color }}>
            {displayCategory.value}%
          </span>
        </div>
      </div>

      <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
        <div className="donut-legend">
          {categories.map((cat, idx) => (
            <div 
              key={idx} 
              className="legend-item"
              onMouseEnter={() => setActiveCategory(cat)}
              onMouseLeave={() => setActiveCategory(null)}
              style={{ opacity: activeCategory && activeCategory.name !== cat.name ? 0.5 : 1 }}
            >
              <span className="legend-dot" style={{ backgroundColor: cat.color }}></span>
              <span>{cat.name === 'Exfil' ? 'Data Exfil' : cat.name}</span>
            </div>
          ))}
        </div>

        <div style={{ textAlign: 'center', marginTop: '4px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)', display: 'block' }}>
            Most Prevalent Vector
          </span>
          <span style={{ fontSize: '15px', fontWeight: '700', color: 'var(--color-blue)' }}>
            {categories[0] ? `${categories[0].name} (${categories[0].value}%)` : 'Awaiting data'}
          </span>
        </div>
      </div>
    </div>
  );
}
