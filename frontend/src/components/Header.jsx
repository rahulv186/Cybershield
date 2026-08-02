import React, { useState, useRef, useEffect } from 'react';
import { Bell, Settings, User } from 'lucide-react';

export default function Header({ 
  notifications, 
  clearNotifications, 
  darkMode, 
  setDarkMode, 
  streamSpeed, 
  setStreamSpeed, 
  isStreaming, 
  setIsStreaming 
}) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const notificationRef = useRef(null);
  const settingsRef = useRef(null);

  // Close dropdowns on outside click
  useEffect(() => {
    function handleClickOutside(event) {
      if (notificationRef.current && !notificationRef.current.contains(event.target)) {
        setShowNotifications(false);
      }
      if (settingsRef.current && !settingsRef.current.contains(event.target)) {
        setShowSettings(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const unreadCount = notifications.filter(n => !n.read).length;

  return (
    <header className="header">
      <div className="header-actions">
        {/* Notification Bell */}
        <div style={{ position: 'relative' }} ref={notificationRef}>
          <button 
            className="icon-btn" 
            onClick={() => {
              setShowNotifications(!showNotifications);
              setShowSettings(false);
            }}
          >
            <Bell size={20} />
            {unreadCount > 0 && (
              <span className="btn-badge">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </button>
          
          {showNotifications && (
            <div className="notification-popover">
              <div className="popover-header">
                <span className="popover-title">Recent Security Alerts</span>
                {notifications.length > 0 && (
                  <button className="popover-clear" onClick={clearNotifications}>
                    Clear All
                  </button>
                )}
              </div>
              <div className="popover-list">
                {notifications.length === 0 ? (
                  <div className="popover-empty">No new notifications</div>
                ) : (
                  notifications.map((notif) => (
                    <div key={notif.id} className="popover-item">
                      <span className={`popover-item-dot pulse-dot-${notif.severity}`}></span>
                      <div className="popover-item-content">
                        <span className="popover-item-text">{notif.message}</span>
                        <span className="popover-item-time">{notif.time}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>
        
        {/* Settings Cog */}
        <div style={{ position: 'relative' }} ref={settingsRef}>
          <button 
            className="icon-btn" 
            onClick={() => {
              setShowSettings(!showSettings);
              setShowNotifications(false);
            }}
          >
            <Settings size={20} />
          </button>
          
          {showSettings && (
            <div className="settings-popover">
              <div>
                <div className="settings-section-title">Aesthetic controls</div>
                <div className="settings-option">
                  <span>Dark Mode</span>
                  <label className="switch">
                    <input 
                      type="checkbox" 
                      checked={darkMode}
                      onChange={() => setDarkMode(!darkMode)}
                    />
                    <span className="slider"></span>
                  </label>
                </div>
              </div>
              
              <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
                <div className="settings-section-title">SOC Simulation</div>
                <div className="settings-option" style={{ marginBottom: '8px' }}>
                  <span>Live Data Stream</span>
                  <label className="switch">
                    <input 
                      type="checkbox" 
                      checked={isStreaming}
                      onChange={() => setIsStreaming(!isStreaming)}
                    />
                    <span className="slider"></span>
                  </label>
                </div>
                <div className="settings-option">
                  <span>Refresh Speed</span>
                  <select 
                    style={{ 
                      padding: '2px 6px', 
                      borderRadius: '4px', 
                      backgroundColor: 'var(--bg-tertiary)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border-color)',
                      fontSize: '11px',
                      fontWeight: '600'
                    }}
                    value={streamSpeed}
                    onChange={(e) => setStreamSpeed(Number(e.target.value))}
                    disabled={!isStreaming}
                  >
                    <option value={2000}>Fast (2s)</option>
                    <option value={5000}>Normal (5s)</option>
                    <option value={10000}>Slow (10s)</option>
                  </select>
                </div>
              </div>
            </div>
          )}
        </div>
        
        {/* Profile Card */}
        <div className="user-profile">
          <div className="user-info">
            <div className="user-name">Security Analyst</div>
            <div className="user-role">soc team alpha</div>
          </div>
          <div className="user-avatar">
            <User size={18} />
          </div>
        </div>
      </div>
    </header>
  );
}
