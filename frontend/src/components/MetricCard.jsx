import React from 'react';

export default function MetricCard({ 
  icon: Icon, 
  color = 'blue', 
  value, 
  label, 
  subtext, 
  badge 
}) {
  return (
    <div className="metric-card hover-card">
      <div className="metric-header">
        <div className={`metric-icon-wrapper ${color}`}>
          <Icon size={20} />
        </div>
        {badge && (
          <span className={`metric-badge ${badge.type}`}>
            {badge.text}
          </span>
        )}
      </div>
      
      <div className="metric-body">
        <span className="metric-value">{value}</span>
        <span className="metric-label">{label}</span>
        <span className="metric-subtext">{subtext}</span>
      </div>
    </div>
  );
}
