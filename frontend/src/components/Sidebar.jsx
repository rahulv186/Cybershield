import React from 'react';
import { Shield, LayoutDashboard, AlertTriangle, Ban, BarChart3, ChevronRight } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab }) {
  const menuItems = [
    { id: 'dashboard', name: 'Dashboard', icon: LayoutDashboard },
    { id: 'incidents', name: 'Incidents', icon: AlertTriangle },
    { id: 'blocked', name: 'Blocked IPs', icon: Ban },
    { id: 'analytics', name: 'Analytics', icon: BarChart3 },
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-logo">
        <Shield size={24} fill="var(--color-blue-light)" />
        <span>CyberShield</span>
      </div>

      <nav className="sidebar-nav">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
              onClick={() => setActiveTab(item.id)}
            >
              <div className="nav-link-content">
                <Icon size={18} />
                <span>{item.name}</span>
              </div>
              {isActive && <ChevronRight size={14} />}
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-footer-title">System Health</div>
        <div className="sidebar-footer-status">
          <span className="pulse-dot pulse-dot-active"></span>
          <span>SOC Engine: Active</span>
        </div>
        <div className="sidebar-footer-version">prototype-v2.4</div>
      </div>
    </div>
  );
}
