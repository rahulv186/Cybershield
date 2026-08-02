import React, { useState } from 'react';
import { MoreHorizontal, ArrowUpDown, X, ShieldAlert, CheckCircle2, FileJson } from 'lucide-react';

export default function ThreatLogsTable({ logs }) {
  const [selectedLog, setSelectedLog] = useState(null);
  const [sortField, setSortField] = useState('time');
  const [sortOrder, setSortOrder] = useState('desc');
  const [showAllLogs, setShowAllLogs] = useState(false);

  const normalizedLogs = (Array.isArray(logs) ? logs : []).map((log, index) => ({
    ...log,
    id: log.id || log._id || index + 1,
    time: log.detectedAt || log.time || 'Unknown',
    type: log.attack_type || log.type || 'Threat Event',
    ip: log.source_ip || log.sourceIP || log.ip || 'Unknown',
    severity: String(log.severity || 'Medium').charAt(0).toUpperCase() + String(log.severity || 'Medium').slice(1),
    status: log.status || (String(log.severity || '').toLowerCase() === 'critical' || String(log.severity || '').toLowerCase() === 'high' ? 'Blocked' : 'Flagged')
  }));

  // Sorting Handler
  const handleSort = (field) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const sortedLogs = [...normalizedLogs].sort((a, b) => {
    const valA = a[sortField];
    const valB = b[sortField];

    if (sortField === 'time') {
      return sortOrder === 'asc'
        ? valA.localeCompare(valB)
        : valB.localeCompare(valA);
    }

    if (sortField === 'severity') {
      const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
      const rankA = severityRank[valA.toLowerCase()] ?? 0;
      const rankB = severityRank[valB.toLowerCase()] ?? 0;
      return sortOrder === 'asc' ? rankA - rankB : rankB - rankA;
    }

    const strA = String(valA).toLowerCase();
    const strB = String(valB).toLowerCase();
    if (strA < strB) return sortOrder === 'asc' ? -1 : 1;
    if (strA > strB) return sortOrder === 'asc' ? 1 : -1;
    return 0;
  });

  const visibleLogs = showAllLogs ? sortedLogs : sortedLogs.slice(0, 5);

  const getStatusDotColor = (status) => {
    switch (status.toLowerCase()) {
      case 'blocked': return 'var(--color-green)';
      case 'contained': return 'var(--color-orange)';
      case 'flagged': return 'var(--color-orange)';
      default: return 'var(--text-secondary)';
    }
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'critical';
      case 'high': return 'high';
      case 'medium': return 'medium';
      case 'low': return 'low';
      default: return '';
    }
  };

  return (
    <div className="table-card">
      <div className="table-header-area">
        <span className="table-title">Recent Automated Blocks</span>
        <div className="table-actions-right">
          <button 
            className="link-action" 
            style={{ background: 'none', border: 'none', font: 'inherit' }}
            onClick={() => setShowAllLogs(!showAllLogs)}
          >
            {showAllLogs ? 'Show Less' : 'View Full Log'}
          </button>
        </div>
      </div>

      <div className="table-wrapper">
        <table className="threat-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('time')} style={{ cursor: 'pointer' }}>
                Time <ArrowUpDown size={12} style={{ display: 'inline-block', marginLeft: '4px' }} />
              </th>
              <th onClick={() => handleSort('type')} style={{ cursor: 'pointer' }}>
                Threat Type <ArrowUpDown size={12} style={{ display: 'inline-block', marginLeft: '4px' }} />
              </th>
              <th onClick={() => handleSort('ip')} style={{ cursor: 'pointer' }}>
                Source IP <ArrowUpDown size={12} style={{ display: 'inline-block', marginLeft: '4px' }} />
              </th>
              <th onClick={() => handleSort('severity')} style={{ cursor: 'pointer' }}>
                Severity <ArrowUpDown size={12} style={{ display: 'inline-block', marginLeft: '4px' }} />
              </th>
              <th onClick={() => handleSort('status')} style={{ cursor: 'pointer' }}>
                Status <ArrowUpDown size={12} style={{ display: 'inline-block', marginLeft: '4px' }} />
              </th>
              <th style={{ textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {visibleLogs.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-secondary)' }}>
                  No matching threat logs found.
                </td>
              </tr>
            ) : (
              visibleLogs.map((log) => (
                <tr key={log.id} style={{ cursor: 'pointer' }} onClick={() => setSelectedLog(log)}>
                  <td>{log.time}</td>
                  <td style={{ fontWeight: 600 }}>{log.type}</td>
                  <td style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{log.ip}</td>
                  <td>
                    <span className={`severity-pill ${getSeverityBadgeClass(log.severity)}`}>
                      {log.severity}
                    </span>
                  </td>
                  <td>
                    <div className="status-cell">
                      <span 
                        className="pulse-dot" 
                        style={{ 
                          backgroundColor: getStatusDotColor(log.status), 
                          boxShadow: `0 0 6px ${getStatusDotColor(log.status)}` 
                        }}
                      ></span>
                      <span style={{ color: getStatusDotColor(log.status), fontWeight: 600 }}>
                        {log.status}
                      </span>
                    </div>
                  </td>
                  <td style={{ textAlign: 'right' }} onClick={(e) => e.stopPropagation()}>
                    <button className="table-action-btn" onClick={() => setSelectedLog(log)}>
                      <MoreHorizontal size={16} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Log Details Modal */}
      {selectedLog && (
        <div className="modal-overlay" onClick={() => setSelectedLog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">Threat Details (Block ID: #{selectedLog.id})</span>
              <button className="modal-close-btn" onClick={() => setSelectedLog(null)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-body">
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px', padding: '10px', borderRadius: '8px', backgroundColor: 'var(--bg-tertiary)' }}>
                {selectedLog.status.toLowerCase() === 'blocked' ? (
                  <CheckCircle2 size={24} color="var(--color-green)" />
                ) : (
                  <ShieldAlert size={24} color="var(--color-orange)" />
                )}
                <div>
                  <div style={{ fontWeight: 700, fontSize: '14px' }}>{selectedLog.type}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>IP blocked from entry point</div>
                </div>
              </div>

              <div className="detail-row">
                <span className="detail-label">Timestamp</span>
                <span className="detail-value">{selectedLog.time}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Source IP Address</span>
                <span className="detail-value mono">{selectedLog.ip}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Severity Level</span>
                <span className={`severity-pill ${getSeverityBadgeClass(selectedLog.severity)}`}>
                  {selectedLog.severity}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Resolution Status</span>
                <span className="detail-value" style={{ color: getStatusDotColor(selectedLog.status) }}>
                  {selectedLog.status}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Location (ISP)</span>
                <span className="detail-value">{selectedLog.details?.isp || 'Not available yet'}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Payload Size</span>
                <span className="detail-value">{selectedLog.details?.payload || selectedLog.evidence || 'Not available yet'}</span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Target Port</span>
                <span className="detail-value mono">{selectedLog.details?.port || selectedLog.protocol || 'Not available yet'}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
