import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import MetricCard from './components/MetricCard';
import ThreatTrendChart from './components/ThreatTrendChart';
import ThreatDistributionChart from './components/ThreatDistributionChart';
import ThreatLogsTable from './components/ThreatLogsTable';
import Incidents from './components/Incidents';
import BlockedIPs from './components/BlockedIPs';
import Analytics from './components/Analytics';
import {
  ShieldCheck,
  Zap,
  Ban,
  ShieldAlert,
  Activity,
  ExternalLink,
  ShieldAlert as AlertIcon,
  CheckCircle,
  FileSpreadsheet,
  Clock
} from 'lucide-react';
import { getThreats } from './api/threatApi';
import { getBlockedIPs } from './api/blockedApi';
import './App.css';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [darkMode, setDarkMode] = useState(false);
  const [streamSpeed, setStreamSpeed] = useState(5000); // 5 seconds
  const [isStreaming, setIsStreaming] = useState(false);

  // Dynamic Stats/Metrics States
  const [threatsPrevented, setThreatsPrevented] = useState(null);
  const [blockedIPs, setBlockedIPs] = useState(null);
  const [todayAttacks, setTodayAttacks] = useState(null);
  const [criticalAlerts, setCriticalAlerts] = useState(null);
  const [systemStatus, setSystemStatus] = useState('Loading');

  const [logs, setLogs] = useState([]);
  const [notifications, setNotifications] = useState([]);
  const [toastMessage, setToastMessage] = useState(null);
  const [statsError, setStatsError] = useState(null);
  const [logsError, setLogsError] = useState(null);

  // Apply Dark Mode Class
  useEffect(() => {
    if (darkMode) {
      document.body.classList.add('dark-mode');
    } else {
      document.body.classList.remove('dark-mode');
    }
  }, [darkMode]);

  useEffect(() => {
    let isMounted = true;
    let pollInterval;

    async function loadThreats() {
      try {
        const [threats, blocked] = await Promise.all([getThreats(), getBlockedIPs()]);
        if (!isMounted) return;
        const threatList = Array.isArray(threats) ? threats : [];
        const blockedList = Array.isArray(blocked) ? blocked : [];
        const today = new Date().toISOString().slice(0, 10);

        setLogs(threatList);
        setThreatsPrevented(threatList.length);
        setBlockedIPs(blockedList.length);
        setTodayAttacks(threatList.filter((threat) => String(threat.detectedAt || '').slice(0, 10) === today).length);
        setCriticalAlerts(threatList.filter((threat) => String(threat.severity || '').toUpperCase() === 'CRITICAL').length);
        setSystemStatus('ONLINE');
        setStatsError(null);
        setLogsError(null);
      } catch (error) {
        if (!isMounted) return;
        setLogsError(error.message || 'Unable to load threat logs');
        setSystemStatus('OFFLINE');
      }
    }

    loadThreats();

    // Poll every 5 seconds to keep metrics updated
    pollInterval = setInterval(loadThreats, 5000);

    return () => {
      isMounted = false;
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, []);

  const clearNotifications = () => {
    setNotifications([]);
  };

  const formatMetricValue = (value) => {
    if (value === null || value === undefined || value === '') return '--';
    return value.toLocaleString ? value.toLocaleString() : String(value);
  };

  // Report Downloader (JSON format)
  const downloadReport = () => {
    const reportData = {
      reportTitle: "ThreatShield SOC Security Report",
      generatedAt: new Date().toString(),
      systemStatus,
      metrics: {
        threatsPrevented,
        blockedIPs,
        todayAttacks,
        criticalAlerts
      },
      recentLogs: logs
    };

    const fileData = JSON.stringify(reportData, null, 2);
    const blob = new Blob([fileData], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ThreatShield_Report_${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />

      <div className="main-content">
        {/* Header Section */}
        <Header
          notifications={notifications}
          clearNotifications={clearNotifications}
          darkMode={darkMode}
          setDarkMode={setDarkMode}
          streamSpeed={streamSpeed}
          setStreamSpeed={setStreamSpeed}
          isStreaming={isStreaming}
          setIsStreaming={setIsStreaming}
        />

        {/* Dashboard Pages Switcher */}
        <main className="dashboard-body">
          {activeTab === 'dashboard' && (
            <>
              {/* Security Dashboard Header Row */}
              <div className="dashboard-title-area">
                <div className="title-info">
                  <h1>Security Dashboard</h1>
                  <p>Real-time threat monitoring and system status overview.</p>
                </div>
                <div className="title-actions">
                  <div className="last-updated">
                    <Clock size={14} />
                    <span>Last updated: {isStreaming ? 'Just now' : 'Paused'}</span>
                  </div>
                  <button className="btn-primary" onClick={downloadReport}>
                    Download Report <ExternalLink size={14} />
                  </button>
                </div>
              </div>

              {/* Statistical Metric Summary Cards (5 columns) */}
              <section className="metrics-grid">
                <MetricCard
                  icon={ShieldCheck}
                  color="green"
                  value={statsError ? 'Error' : systemStatus}
                  label="Engine Status"
                  subtext={statsError ? 'backend unavailable' : 'soc engine online'}
                />
                <MetricCard
                  icon={Zap}
                  color="orange"
                  value={statsError ? 'Error' : formatMetricValue(threatsPrevented)}
                  label="Threats Detected"
                  subtext="total blocked events"
                  badge={{ text: statsError ? 'N/A' : '+12%', type: 'red' }}
                />
                <MetricCard
                  icon={Ban}
                  color="blue"
                  value={statsError ? 'Error' : formatMetricValue(blockedIPs)}
                  label="Blocked IPs"
                  subtext="active blacklisted hosts"
                />
                <MetricCard
                  icon={ShieldAlert}
                  color="red"
                  value={statsError ? 'Error' : formatMetricValue(criticalAlerts)}
                  label="Critical Alerts"
                  subtext="requiring immediate action"
                  badge={{ text: statsError ? 'N/A' : 'STABLE', type: 'gray' }}
                />
                <MetricCard
                  icon={Activity}
                  color="blue"
                  value={statsError ? 'Error' : formatMetricValue(todayAttacks)}
                  label="Today's Attacks"
                  subtext="detection volume spike"
                  badge={{ text: statsError ? 'N/A' : '+15%', type: 'red' }}
                />
              </section>

              {/* Chart Grid (Line Chart & Donut Chart) */}
              <section className="charts-grid">
                <ThreatTrendChart />
                <ThreatDistributionChart />
              </section>

              {statsError && <div className="table-card" style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>TODO: Backend endpoint required for stats API.</div>}
              {logsError && <div className="table-card" style={{ padding: '12px 16px', color: 'var(--text-secondary)' }}>TODO: Backend endpoint required for threat logs API.</div>}

              {/* Threat Logging Table */}
              <ThreatLogsTable logs={logs} />
            </>
          )}

          {activeTab === 'incidents' && (
            <Incidents />
          )}

          {activeTab === 'blocked' && (
            <BlockedIPs />
          )}

          {activeTab === 'analytics' && (
            <Analytics />
          )}
        </main>

        {/* Global Footer */}
        <footer className="footer">
          <span>&copy; 2026 ThreatShield Enterprise. All rights reserved.</span>
          <div className="footer-links">
            <a href="#docs">Documentation</a>
            <a href="#support">Support Portal</a>
            <a href="#privacy">Privacy Policy</a>
          </div>
        </footer>
      </div>

      {/* Floating Critical Alert Toast Overlay */}
      {toastMessage && (
        <div className="toast">
          <AlertIcon size={16} color="var(--color-red)" />
          <span className="toast-content">{toastMessage}</span>
        </div>
      )}
    </div>
  );
}
