import React, { useEffect, useState } from 'react';
import { 
  Search, 
  Download, 
  ChevronDown, 
  Calendar, 
  X, 
  ShieldAlert, 
  Ban, 
  Activity, 
  Terminal,
  ArrowUpDown,
  Lock,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { getThreats, normalizeThreats } from '../api/threatApi';

function ThreatDetailRow({ label, value, mono = false }) {
  return (
    <div className="visily-data-row">
      <span className="visily-label">{label}</span>
      <span className="visily-colon">:</span>
      <span className={`visily-value ${mono ? 'mono' : ''}`}>{value}</span>
    </div>
  );
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  
  // Filter States
  const [search, setSearch] = useState('');
  const [threatFilter, setThreatFilter] = useState('All');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [timeframe, setTimeframe] = useState('24h');

  // Handle row sorting (can just default to detection time desc)
  const [sortOrder, setSortOrder] = useState('desc');

  useEffect(() => {
    let isMounted = true;

    async function loadIncidents() {
      try {
        setIsLoading(true);
        const threats = await getThreats();
        if (!isMounted) return;
        const nextIncidents = normalizeThreats(threats).map((threat, index) => ({
          ...threat,
          id: threat._id || threat.id || `INC-${index + 1}`,
          icon: threat.severity === 'Critical' ? ShieldAlert : threat.attack_type?.toLowerCase().includes('sql') ? Terminal : Activity,
          iconColor: threat.severity === 'Critical' ? 'var(--color-red)' : 'var(--color-blue)',
          iconBg: threat.severity === 'Critical' ? 'var(--color-red-light)' : 'var(--color-blue-light)',
          attackTypeLabel: threat.attack_type || 'Threat Event',
          type: threat.attack_type || 'Threat Event',
          sourceIP: threat.source_ip || 'Unknown',
          destIP: threat.destination_ip || 'Unknown',
          protocol: threat.protocol || 'Unknown',
          time: threat.detectedAt || threat.time || new Date().toISOString(),
          severity: threat.severity || 'Medium',
          status: threat.status || 'Flagged',
          confidence: 'N/A',
          description: threat.description || 'No details available',
          evidence: threat.evidence || 'Pending backend data',
          recommendation: threat.recommendation || 'No recommendation available'
        }));
        setIncidents(nextIncidents);
        setError(null);
      } catch (err) {
        if (!isMounted) return;
        setError(err.message || 'Unable to load incidents');
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadIncidents();
    return () => { isMounted = false; };
  }, []);

  const filteredIncidents = incidents.filter(inc => {
    const searchText = search.toLowerCase();
    const matchesSearch = !searchText || [
      inc.sourceIP,
      inc.destIP,
      inc.id,
      inc.attack_type,
      inc.type,
      inc.severity,
      inc.protocol
    ].some((value) => String(value || '').toLowerCase().includes(searchText));

    const matchesThreat = threatFilter === 'All' || inc.attack_type === threatFilter || inc.type === threatFilter;
    const matchesSeverity = severityFilter === 'All' || inc.severity === severityFilter;
    const matchesStatus = statusFilter === 'All' || inc.status === statusFilter;

    return matchesSearch && matchesThreat && matchesSeverity && matchesStatus;
  });

  const getSeverityBadgeStyle = (sev) => {
    switch (sev.toLowerCase()) {
      case 'critical': 
        return { backgroundColor: 'var(--color-red)', color: '#ffffff' };
      case 'high': 
        return { backgroundColor: '#f1f5f9', color: '#1e293b', border: '1px solid #cbd5e1' };
      case 'medium': 
        return { backgroundColor: 'var(--color-orange)', color: '#ffffff' };
      case 'low': 
        return { backgroundColor: 'var(--color-blue)', color: '#ffffff' };
      default: 
        return {};
    }
  };

  const getStatusBadgeStyle = (status) => {
    switch (status.toLowerCase()) {
      case 'blocked':
        return { borderColor: '#fca5a5', color: '#ef4444', backgroundColor: '#fff5f5' };
      case 'flagged':
        return { borderColor: '#cbd5e1', color: '#64748b', backgroundColor: '#f8fafc' };
      case 'investigating':
        return { borderColor: '#93c5fd', color: '#2563eb', backgroundColor: '#eff6ff' };
      default:
        return {};
    }
  };

  const downloadCSVReport = () => {
    const headers = ['Incident ID,Threat Type,Source IP,Destination IP,Protocol,Detection Time,Severity,Status,Confidence\n'];
    const rows = filteredIncidents.map(inc => 
      `"${inc.id}","${inc.type}","${inc.sourceIP}","${inc.destIP}","${inc.protocol}","${inc.time}","${inc.severity}","${inc.status}","${inc.confidence}"`
    ).join('\n');
    
    const blob = new Blob([...headers, rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ThreatShield_Incidents_Report.csv`;
    link.click();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Title Header */}
      <div className="dashboard-title-area">
        <div className="title-info">
          <h1>Threat Incidents</h1>
          <p>Investigate and manage real-time security events across your infrastructure.</p>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }} className="last-updated">
          <span className="pulse-dot pulse-dot-active"></span>
          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-blue)' }}>
            Live Monitoring Active
          </span>
        </div>
      </div>

      {/* Filter and Control Panel card */}
      <div className="table-card">
        
        {/* Top filter row */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
          
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center', flex: 1 }}>
            
            {/* Search Input */}
            <div className="table-search" style={{ width: '260px' }}>
              <Search size={14} className="text-secondary" />
              <input
                type="text"
                placeholder="Filter by IP, Incident ID..."
                className="table-search-input"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            {/* Dropdown 1: Threat Type */}
            <div className="select-wrapper" style={{ position: 'relative' }}>
              <select
                className="dropdown-filter"
                value={threatFilter}
                onChange={(e) => setThreatFilter(e.target.value)}
              >
                <option value="All">All Threats</option>
                <option value="DDoS Attack">DDoS Attack</option>
                <option value="SQL Injection">SQL Injection</option>
                <option value="Port Scanning">Port Scanning</option>
                <option value="Unauthorized Access">Unauthorized Access</option>
                <option value="Beacon Detection">Beacon Detection</option>
                <option value="Data Exfiltration">Data Exfiltration</option>
              </select>
              <ChevronDown size={14} className="dropdown-arrow-icon" />
            </div>

            {/* Dropdown 2: Severity */}
            <div className="select-wrapper" style={{ position: 'relative' }}>
              <select
                className="dropdown-filter"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
              >
                <option value="All">All Severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
              <ChevronDown size={14} className="dropdown-arrow-icon" />
            </div>

            {/* Dropdown 3: Status */}
            <div className="select-wrapper" style={{ position: 'relative' }}>
              <select
                className="dropdown-filter"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="All">All Statuses</option>
                <option value="Blocked">Blocked</option>
                <option value="Flagged">Flagged</option>
                <option value="Investigating">Investigating</option>
              </select>
              <ChevronDown size={14} className="dropdown-arrow-icon" />
            </div>

            {/* Timeframe selector */}
            <div className="timeframe-picker">
              <Calendar size={14} />
              <span>Last 24 Hours</span>
            </div>

          </div>

          {/* Export action */}
          <button 
            className="icon-btn" 
            onClick={downloadCSVReport} 
            title="Download CSV Log"
            style={{ border: '1px solid var(--border-color)', borderRadius: '8px', height: '36px', width: '36px' }}
          >
            <Download size={16} />
          </button>
        </div>

        {/* Incidents Data Table */}
        {isLoading ? (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)' }}>Loading incidents...</div>
        ) : error ? (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)' }}>Unable to load incident data from the backend.</div>
        ) : (
        <div className="table-wrapper">
          <table className="threat-table">
            <thead>
              <tr>
                <th>Threat Type</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Detection Time <ArrowUpDown size={10} style={{ display: 'inline-block', marginLeft: '2px' }} /></th>
                <th>Severity</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-secondary)' }}>
                    No matching incidents found.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => {
                  const IncidentIcon = inc.icon;
                  return (
                    <tr 
                      key={inc.id} 
                      onClick={() => setSelectedIncident(inc)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontWeight: 600 }}>
                          <div style={{ 
                            width: '28px', 
                            height: '28px', 
                            borderRadius: '6px', 
                            display: 'flex', 
                            alignItems: 'center', 
                            justifyContent: 'center',
                            backgroundColor: inc.iconBg,
                            color: inc.iconColor
                          }}>
                            <IncidentIcon size={14} />
                          </div>
                          <span>{inc.attack_type || inc.type}</span>
                        </div>
                      </td>
                      <td style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{inc.sourceIP}</td>
                      <td style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{inc.destIP}</td>
                      <td>
                        <span style={{ 
                          fontSize: '10px', 
                          fontWeight: 700, 
                          backgroundColor: 'var(--bg-tertiary)', 
                          padding: '2px 8px', 
                          borderRadius: '4px',
                          color: 'var(--text-secondary)'
                        }}>
                          {inc.protocol}
                        </span>
                      </td>
                      <td>{inc.time}</td>
                      <td>
                        <span className="severity-pill" style={getSeverityBadgeStyle(inc.severity)}>
                          {inc.severity}
                        </span>
                      </td>
                      <td>
                        <span className="incident-status-pill" style={getStatusBadgeStyle(inc.status)}>
                          {inc.status}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        )}

        {/* Table footer & pagination mockup */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '12px', fontSize: '13px', color: 'var(--text-secondary)' }}>
          <span>Showing 1 to {filteredIncidents.length} of 1,244 security incidents</span>
          
          <div className="pagination-bar">
            <button className="pagination-btn"><ChevronLeft size={14} /> Previous</button>
            <button className="pagination-btn active">1</button>
            <button className="pagination-btn">2</button>
            <button className="pagination-btn">3</button>
            <button className="pagination-btn">Next <ChevronRight size={14} /></button>
          </div>
        </div>

      </div>

      {/* Threat Detected Modal */}
      {selectedIncident && (
        <div className="modal-overlay" onClick={() => setSelectedIncident(null)}>
          <div className="visily-modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="visily-modal-header">
              <h2 className="visily-modal-title">THREAT DETECTED</h2>
              <button
                type="button"
                className="visily-modal-close"
                onClick={() => setSelectedIncident(null)}
                aria-label="Close threat details"
              >
                <X size={20} />
              </button>
            </div>

            <div className="visily-modal-body">
              <div className="visily-data-box visily-threat-box">
                <ThreatDetailRow
                  label="Attack Type"
                  value={selectedIncident.attack_typeLabel || selectedIncident.type}
                />
                <ThreatDetailRow label="Severity" value={selectedIncident.severity.toUpperCase()} />
                <ThreatDetailRow label="Time" value={selectedIncident.detectedAt} />
                <ThreatDetailRow label="Source" value={selectedIncident.source_ip} mono />
                <ThreatDetailRow label="Destination" value={selectedIncident.destination_ip} mono />
                <ThreatDetailRow label="Description" value={selectedIncident.description} />
                <ThreatDetailRow label="Evidence" value={selectedIncident.evidence} />
                <ThreatDetailRow label="Recommendation" value={selectedIncident.recommendation} />

                <div className="visily-box-grip">
                  <span>//</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
