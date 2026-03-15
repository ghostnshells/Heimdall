import React from 'react';
import {
    LayoutDashboard,
    RefreshCw,
    Clock,
    Radio,
    ChevronLeft,
    ChevronRight,
    Activity,
    Link2,
    LogIn,
    LogOut,
    Settings
} from 'lucide-react';
import './Sidebar.css';

const Sidebar = ({
    vulnCounts = {},
    lastUpdated,
    onRefresh,
    isLoading,
    isCollapsed = false,
    onToggleCollapse,
    activeView = 'dashboard',
    onActiveViewChange,
    isLoggedIn = false,
    user = null,
    onSignInClick,
    onLogoutClick,
    onSettingsClick,
}) => {
    // Get total for all assets
    const getAllStats = () => {
        let total = 0;
        let critical = 0;

        Object.values(vulnCounts).forEach(counts => {
            total += counts.total || 0;
            critical += counts.critical || 0;
        });

        return { total, critical };
    };

    const allStats = getAllStats();

    return (
        <aside className={`sidebar ${isCollapsed ? 'collapsed' : ''}`}>
            <div className="sidebar-header">
                <div className="sidebar-logo">
                    <div className="sidebar-logo-icon">
                        <img src={`${import.meta.env.BASE_URL}panoptes-logo.png`} alt="Panoptes" className="sidebar-logo-img" />
                    </div>
                    {!isCollapsed && (
                        <div className="sidebar-logo-text">
                            <span>PANOPTES</span>
                        </div>
                    )}
                </div>
                <button
                    className="sidebar-toggle"
                    onClick={onToggleCollapse}
                    title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                >
                    {isCollapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
                </button>
            </div>

            <div className="sidebar-content">
                {/* Overview - All Assets */}
                <div className="sidebar-section">
                    {!isCollapsed && <div className="sidebar-section-title">Overview</div>}
                    <nav className="sidebar-nav">
                        <div
                            className={`sidebar-nav-item ${activeView === 'dashboard' ? 'active' : ''}`}
                            onClick={() => onActiveViewChange && onActiveViewChange('dashboard')}
                            title="All Assets"
                        >
                            <LayoutDashboard />
                            {!isCollapsed && <span className="sidebar-nav-item-text">All Assets</span>}
                            {allStats.total > 0 && (
                                <span className={`sidebar-nav-item-badge ${allStats.critical > 0 ? 'critical' : ''}`}>
                                    {allStats.total}
                                </span>
                            )}
                        </div>
                    </nav>
                </div>

                {/* Monitor Section */}
                <div className="sidebar-section">
                    {!isCollapsed && <div className="sidebar-section-title">Monitor</div>}
                    <nav className="sidebar-nav">
                        <div
                            className={`sidebar-nav-item ${activeView === 'pulse' ? 'active' : ''}`}
                            onClick={() => onActiveViewChange && onActiveViewChange('pulse')}
                            title="The Pulse"
                        >
                            <Activity />
                            {!isCollapsed && <span className="sidebar-nav-item-text">The Pulse</span>}
                        </div>
                        <div
                            className={`sidebar-nav-item ${activeView === 'killchain' ? 'active' : ''}`}
                            onClick={() => onActiveViewChange && onActiveViewChange('killchain')}
                            title="Kill Chain"
                        >
                            <Link2 />
                            {!isCollapsed && <span className="sidebar-nav-item-text">Kill Chain</span>}
                        </div>
                    </nav>
                </div>

                {!isCollapsed && (
                    <div className="sidebar-section">
                        <div className="sidebar-section-title">Data Source</div>
                        <div className="data-source-info">
                            <Radio size={14} />
                            <span>Live NVD API</span>
                        </div>
                        <p className="data-source-note">
                            All vulnerability data is fetched from the official National Vulnerability Database (NVD).
                            Click any CVE to verify at nvd.nist.gov.
                        </p>
                    </div>
                )}
            </div>

            <div className="sidebar-footer">
                {lastUpdated && !isCollapsed && (
                    <div className="sidebar-footer-info">
                        <Clock />
                        <span>Updated {formatTimeAgo(new Date(lastUpdated))}</span>
                    </div>
                )}
                <button
                    className="sidebar-refresh-btn"
                    onClick={onRefresh}
                    disabled={isLoading}
                    title={isLoading ? 'Fetching...' : 'Refresh Data'}
                >
                    <RefreshCw className={isLoading ? 'spinning' : ''} />
                    {!isCollapsed && (isLoading ? 'Fetching...' : 'Refresh Data')}
                </button>
                {isLoading && !isCollapsed && (
                    <p className="sidebar-loading-note">
                        NVD API has rate limits. This may take a few minutes.
                    </p>
                )}

                {/* Auth section */}
                <div className="sidebar-auth">
                    {isLoggedIn ? (
                        <div className="sidebar-auth-user">
                            {!isCollapsed && (
                                <span className="sidebar-user-email" title={user?.email}>
                                    {user?.email}
                                </span>
                            )}
                            <div className="sidebar-auth-actions">
                                <button
                                    className="sidebar-auth-icon-btn"
                                    onClick={onSettingsClick}
                                    title="Settings"
                                >
                                    <Settings size={16} />
                                </button>
                                <button
                                    className="sidebar-auth-icon-btn"
                                    onClick={onLogoutClick}
                                    title="Sign Out"
                                >
                                    <LogOut size={16} />
                                </button>
                            </div>
                        </div>
                    ) : (
                        <button
                            className="sidebar-signin-btn"
                            onClick={onSignInClick}
                            title="Sign In"
                        >
                            <LogIn size={16} />
                            {!isCollapsed && <span>Sign In</span>}
                        </button>
                    )}
                </div>
            </div>
        </aside>
    );
};

// Format time ago helper
const formatTimeAgo = (date) => {
    const seconds = Math.floor((new Date() - date) / 1000);

    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
};

export default Sidebar;
