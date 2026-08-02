import React, { useEffect, useMemo, useState } from 'react';
import { Search, Download, Filter, Lock, ShieldOff, X } from 'lucide-react';
import { getBlockedIPs, removeBlockedIP } from '../api/blockedApi';
import { getThreats } from '../api/threatApi';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Format an ISO date as "YYYY-MM-DD HH:mm:ss IST"
 * using the Asia/Kolkata timezone (IST = UTC+5:30).
 */
function formatIST(isoString) {
  if (!isoString) return '—';
  const d = new Date(isoString);
  if (isNaN(d)) return String(isoString);

  const opts = {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  };

  const parts = new Intl.DateTimeFormat('en-GB', opts).formatToParts(d);
  const get = (type) => parts.find((p) => p.type === type)?.value ?? '00';
  return `${get('year')}-${get('month')}-${get('day')} ${get('hour')}:${get('minute')}:${get('second')} IST`;
}

/**
 * Pull attack_type, detectedAt, protocol from wherever they live.
 * Priority: reason object → matched threat from threats list → fallback '—'
 */
function enrichEntry(entry, threatsByIp) {
  const r = entry.reason;
  const fromReason = r && typeof r === 'object' ? r : null;

  const matchedThreats = threatsByIp[entry.blockedIP] || [];
  const latestThreat =
    matchedThreats.length > 0
      ? matchedThreats.reduce((a, b) =>
          new Date(a.detectedAt) > new Date(b.detectedAt) ? a : b
        )
      : null;

  // Build complete unified threat details object for display
  const threatDetails = {
    source_ip: entry.blockedIP,
    destination_ip: fromReason?.destination_ip || latestThreat?.destination_ip || '—',
    attack_type: fromReason?.attack_type || latestThreat?.attack_type || (typeof r === 'string' ? r : '—'),
    protocol: fromReason?.protocol || latestThreat?.protocol || '—',
    severity: fromReason?.severity || latestThreat?.severity || 'MEDIUM',
    detectedAt: fromReason?.detectedAt || latestThreat?.detectedAt || entry.blockedAt,
    description: fromReason?.description || latestThreat?.description || 'No detailed description available.',
    evidence: fromReason?.evidence || latestThreat?.evidence || 'No payload/evidence payload matching this incident.',
    recommendation: fromReason?.recommendation || latestThreat?.recommendation || 'Perimeter IP block has been applied. Monitor traffic for spoofing.',
    status: 'Blocked'
  };

  return {
    ...entry,
    attack_type: threatDetails.attack_type,
    detectedAt: threatDetails.detectedAt,
    protocol: threatDetails.protocol,
    threatDetails
  };
}

// Protocol badge colour map
const PROTOCOL_COLORS = {
  TCP:   { bg: 'rgba(59,130,246,0.12)', color: '#3b82f6', border: 'rgba(59,130,246,0.3)' },
  UDP:   { bg: 'rgba(168,85,247,0.12)', color: '#a855f7', border: 'rgba(168,85,247,0.3)' },
  ICMP:  { bg: 'rgba(249,115,22,0.12)', color: '#f97316', border: 'rgba(249,115,22,0.3)' },
  HTTP:  { bg: 'rgba(16,185,129,0.12)', color: '#10b981', border: 'rgba(16,185,129,0.3)' },
  HTTPS: { bg: 'rgba(16,185,129,0.12)', color: '#10b981', border: 'rgba(16,185,129,0.3)' },
  DNS:   { bg: 'rgba(234,179,8,0.12)',  color: '#eab308', border: 'rgba(234,179,8,0.3)' },
};

function ProtocolBadge({ protocol }) {
  const p = (protocol || '').toUpperCase();
  const style = PROTOCOL_COLORS[p] || {
    bg: 'var(--bg-tertiary)',
    color: 'var(--text-secondary)',
    border: 'var(--border-color)',
  };
  return (
    <span
      style={{
        backgroundColor: style.bg,
        color: style.color,
        border: `1px solid ${style.border}`,
        borderRadius: '9999px',
        padding: '3px 10px',
        fontSize: '11px',
        fontWeight: 700,
        letterSpacing: '0.04em',
        whiteSpace: 'nowrap',
        fontFamily: 'monospace',
      }}
    >
      {p || '—'}
    </span>
  );
}

function AttackTypeBadge({ type }) {
  return (
    <span
      style={{
        backgroundColor: 'rgba(239,68,68,0.1)',
        color: 'var(--color-red, #ef4444)',
        border: '1px solid rgba(239,68,68,0.25)',
        borderRadius: '9999px',
        padding: '3px 10px',
        fontSize: '11px',
        fontWeight: 700,
        whiteSpace: 'nowrap',
      }}
    >
      {type || '—'}
    </span>
  );
}

function getSeverityBadgeClass(severity) {
  switch (String(severity).toLowerCase()) {
    case 'critical': return 'critical';
    case 'high': return 'high';
    case 'medium': return 'medium';
    case 'low': return 'low';
    default: return '';
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function BlockedIPs() {
  const [blockedList, setBlockedList] = useState([]);
  const [search, setSearch] = useState('');
  const [attackFilter, setAttackFilter] = useState('All');
  const [protocolFilter, setProtocolFilter] = useState('All');

  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [removingId, setRemovingId] = useState(null);

  // Modal dialog state
  const [selectedEntry, setSelectedEntry] = useState(null);

  // Fetch blocked IPs and threats in parallel, then enrich
  useEffect(() => {
    let isMounted = true;

    async function load() {
      try {
        setIsLoading(true);
        const [blocked, threats] = await Promise.all([getBlockedIPs(), getThreats()]);
        if (!isMounted) return;

        const threatsByIp = {};
        (Array.isArray(threats) ? threats : []).forEach((t) => {
          const ip = t.source_ip;
          if (!ip) return;
          if (!threatsByIp[ip]) threatsByIp[ip] = [];
          threatsByIp[ip].push(t);
        });

        const enriched = (Array.isArray(blocked) ? blocked : []).map((entry) =>
          enrichEntry(entry, threatsByIp)
        );

        setBlockedList(enriched);
        setError(null);
      } catch (err) {
        if (!isMounted) return;
        setError(err.message || 'Unable to load blocked IPs');
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    load();
    return () => { isMounted = false; };
  }, []);

  // Listen to Escape key to close the modal
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') {
        setSelectedEntry(null);
      }
    }
    if (selectedEntry) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [selectedEntry]);

  // Derive dynamic filter options from actual data
  const attackOptions = useMemo(() => {
    const unique = new Set(blockedList.map((i) => i.attack_type).filter((v) => v && v !== '—'));
    return ['All', ...Array.from(unique).sort()];
  }, [blockedList]);

  const protocolOptions = useMemo(() => {
    const unique = new Set(blockedList.map((i) => i.protocol).filter((v) => v && v !== '—'));
    return ['All', ...Array.from(unique).sort()];
  }, [blockedList]);

  const filteredEntries = useMemo(() => {
    return blockedList.filter((item) => {
      const query = search.trim().toLowerCase();
      const ip = (item.blockedIP || '').toLowerCase();
      const attack = (item.attack_type || '').toLowerCase();
      const proto = (item.protocol || '').toLowerCase();

      const matchesSearch =
        !query || ip.includes(query) || attack.includes(query) || proto.includes(query);

      const matchesAttack =
        attackFilter === 'All' || item.attack_type === attackFilter;

      const matchesProtocol =
        protocolFilter === 'All' || item.protocol === protocolFilter;

      return matchesSearch && matchesAttack && matchesProtocol;
    });
  }, [blockedList, search, attackFilter, protocolFilter]);

  const handleUnblock = async (entry) => {
    const id = entry._id;
    setRemovingId(id);
    try {
      await removeBlockedIP(entry.blockedIP);
      setBlockedList((prev) => prev.filter((item) => item._id !== id));
      if (selectedEntry && selectedEntry._id === id) {
        setSelectedEntry(null);
      }
    } catch (err) {
      setError(err.message || 'Unable to remove blocked IP');
    } finally {
      setRemovingId(null);
    }
  };

  const downloadRegistry = () => {
    const headers = 'IP Address,Attack Type,Detected At,Protocol\n';
    const rows = filteredEntries
      .map((entry) =>
        `"${entry.blockedIP}","${entry.attack_type}","${formatIST(entry.detectedAt)}","${entry.protocol}"`
      )
      .join('\n');

    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'ThreatShield_Blocked_IP_Registry.csv';
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Header */}
      <div className="dashboard-title-area">
        <div className="title-info">
          <h1>Blocked IPs</h1>
          <p>Manage perimeter security and analyze blocked network entities.</p>
        </div>

        <div className="title-actions">
          <button
            className="btn-chart-action"
            onClick={downloadRegistry}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Download size={14} />
            Export Registry
          </button>
          <button
            className="btn-chart-action"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: 'var(--color-blue)',
              color: '#ffffff',
            }}
          >
            <Lock size={14} />
            Block Manual IP
          </button>
        </div>
      </div>

      {/* Table Card */}
      <div className="table-card">
        {/* Toolbar */}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
          }}
        >
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '10px',
              alignItems: 'center',
              flex: 1,
            }}
          >
            {/* Search */}
            <div className="table-search" style={{ width: '300px' }}>
              <Search size={14} className="text-secondary" />
              <input
                type="text"
                className="table-search-input"
                placeholder="Filter by IP, attack type, or protocol..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>

            {/* Attack Type filter */}
            <div className="timeframe-picker">
              <Filter size={14} />
              <select
                className="blocked-inline-select"
                value={attackFilter}
                onChange={(e) => setAttackFilter(e.target.value)}
              >
                {attackOptions.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt === 'All' ? 'Attack Type' : opt}
                  </option>
                ))}
              </select>
            </div>

            {/* Protocol filter */}
            <div className="timeframe-picker">
              <Filter size={14} />
              <select
                className="blocked-inline-select"
                value={protocolFilter}
                onChange={(e) => setProtocolFilter(e.target.value)}
              >
                {protocolOptions.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt === 'All' ? 'Protocol' : opt}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <span
            style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600 }}
          >
            Showing {filteredEntries.length} of {blockedList.length} blocked address
            {blockedList.length !== 1 ? 'es' : ''}
          </span>
        </div>

        {/* Table */}
        {isLoading ? (
          <div
            style={{ padding: '24px', textAlign: 'center', color: 'var(--text-secondary)' }}
          >
            Loading blocked IPs…
          </div>
        ) : error ? (
          <div
            style={{ padding: '24px', textAlign: 'center', color: 'var(--color-red)' }}
          >
            {error}
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="threat-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Attack Type</th>
                  <th>Detected At</th>
                  <th>Protocol</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredEntries.length === 0 ? (
                  <tr>
                    <td
                      colSpan="5"
                      style={{
                        textAlign: 'center',
                        padding: '28px',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      No blocked IP entries found.
                    </td>
                  </tr>
                ) : (
                  filteredEntries.map((entry) => {
                    const isRemoving = removingId === entry._id;
                    return (
                      <tr
                        key={entry._id}
                        style={{ cursor: 'pointer' }}
                        onClick={() => setSelectedEntry(entry)}
                      >
                        {/* IP Address */}
                        <td
                          style={{
                            fontWeight: 700,
                            color: 'var(--color-blue)',
                            fontFamily: 'monospace',
                            letterSpacing: '0.03em',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {entry.blockedIP}
                        </td>

                        {/* Attack Type */}
                        <td>
                          <AttackTypeBadge type={entry.attack_type} />
                        </td>

                        {/* Detected At */}
                        <td style={{ whiteSpace: 'nowrap' }}>
                          <span
                            style={{
                              fontVariantNumeric: 'tabular-nums',
                              fontSize: '12px',
                              color: 'var(--text-primary)',
                            }}
                          >
                            {formatIST(entry.detectedAt)}
                          </span>
                        </td>

                        {/* Protocol */}
                        <td>
                          <ProtocolBadge protocol={entry.protocol} />
                        </td>

                        {/* Unblock Action */}
                        <td onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => handleUnblock(entry)}
                            disabled={isRemoving}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '5px',
                              padding: '4px 10px',
                              fontSize: '11px',
                              fontWeight: 700,
                              borderRadius: '6px',
                              border: '1px solid var(--color-red)',
                              background: 'transparent',
                              color: 'var(--color-red)',
                              cursor: isRemoving ? 'not-allowed' : 'pointer',
                              opacity: isRemoving ? 0.5 : 1,
                              transition: 'background 0.15s, color 0.15s',
                            }}
                            onMouseEnter={(e) => {
                              if (!isRemoving) {
                                e.currentTarget.style.background = 'var(--color-red)';
                                e.currentTarget.style.color = '#fff';
                              }
                            }}
                            onMouseLeave={(e) => {
                              e.currentTarget.style.background = 'transparent';
                              e.currentTarget.style.color = 'var(--color-red)';
                            }}
                          >
                            <ShieldOff size={12} />
                            {isRemoving ? 'Removing…' : 'Unblock'}
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Details Centered Modal/Dialog */}
      {selectedEntry && (
        <div className="modal-overlay" onClick={() => setSelectedEntry(null)}>
          <div
            className="modal-content"
            style={{ width: '600px', maxWidth: '90%' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <span className="modal-title" style={{ fontSize: '16px', fontWeight: 700 }}>
                Blocked IP Security Details
              </span>
              <button className="modal-close-btn" onClick={() => setSelectedEntry(null)}>
                <X size={18} />
              </button>
            </div>
            <div className="modal-body" style={{ maxHeight: '80vh', overflowY: 'auto', gap: '14px' }}>
              
              {/* Top Banner indicating Blocked Status */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '12px 16px',
                borderRadius: '8px',
                backgroundColor: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.15)',
                marginBottom: '4px'
              }}>
                <ShieldOff size={24} color="var(--color-red)" />
                <div>
                  <div style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)' }}>
                    Host Block Active
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                    Perimeter firewall is actively rejecting traffic from this origin.
                  </div>
                </div>
              </div>

              {/* Source IP */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'center' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Source IP</span>
                <span style={{ flex: 1, fontFamily: 'monospace', fontWeight: 700, color: 'var(--color-blue)', fontSize: '14px', letterSpacing: '0.03em' }}>
                  {selectedEntry.threatDetails.source_ip}
                </span>
              </div>

              {/* Destination IP */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'center' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Destination IP</span>
                <span style={{ flex: 1, fontFamily: 'monospace', fontWeight: 700, color: 'var(--text-primary)', fontSize: '14px', letterSpacing: '0.03em' }}>
                  {selectedEntry.threatDetails.destination_ip}
                </span>
              </div>

              {/* Attack Type */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'center' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Attack Type</span>
                <div style={{ flex: 1 }}>
                  <AttackTypeBadge type={selectedEntry.threatDetails.attack_type} />
                </div>
              </div>

              {/* Protocol */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'center' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Protocol</span>
                <div style={{ flex: 1 }}>
                  <ProtocolBadge protocol={selectedEntry.threatDetails.protocol} />
                </div>
              </div>

              {/* Severity */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'center' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Severity</span>
                <div style={{ flex: 1 }}>
                  <span className={`severity-pill ${getSeverityBadgeClass(selectedEntry.threatDetails.severity)}`}>
                    {selectedEntry.threatDetails.severity}
                  </span>
                </div>
              </div>

              {/* Detection Time */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'center' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Detection Time</span>
                <span style={{ flex: 1, fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>
                  {formatIST(selectedEntry.threatDetails.detectedAt)}
                </span>
              </div>

              {/* Status */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'center' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Status</span>
                <div style={{ flex: 1 }}>
                  <span style={{
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    color: 'var(--color-red)',
                    border: '1px solid rgba(239, 68, 68, 0.25)',
                    borderRadius: '9999px',
                    padding: '3px 10px',
                    fontSize: '11px',
                    fontWeight: 700,
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em'
                  }}>
                    {selectedEntry.threatDetails.status}
                  </span>
                </div>
              </div>

              {/* Description */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'flex-start' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Description</span>
                <span style={{ flex: 1, lineHeight: '1.5', color: 'var(--text-primary)', fontSize: '13px', wordBreak: 'break-word' }}>
                  {selectedEntry.threatDetails.description}
                </span>
              </div>

              {/* Evidence */}
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border-color)', paddingBottom: '10px', gap: '16px', alignItems: 'flex-start' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Evidence</span>
                <span style={{
                  flex: 1,
                  lineHeight: '1.5',
                  color: 'var(--text-primary)',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                  backgroundColor: 'var(--bg-tertiary)',
                  padding: '8px 12px',
                  borderRadius: '6px',
                  border: '1px solid var(--border-color)',
                  wordBreak: 'break-all',
                  whiteSpace: 'pre-wrap'
                }}>
                  {selectedEntry.threatDetails.evidence}
                </span>
              </div>

              {/* Recommendation */}
              <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
                <span style={{ minWidth: '140px', color: 'var(--text-secondary)', fontWeight: 600, fontSize: '13px' }}>Recommendation</span>
                <span style={{ flex: 1, lineHeight: '1.5', color: 'var(--text-primary)', fontSize: '13px', wordBreak: 'break-word' }}>
                  {selectedEntry.threatDetails.recommendation}
                </span>
              </div>

            </div>
          </div>
        </div>
      )}
    </div>
  );
}
