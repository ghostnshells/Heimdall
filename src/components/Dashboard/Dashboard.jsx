import React from 'react';
import { Shield, AlertTriangle, CheckCircle2 } from 'lucide-react';
import AssetCard, { AssetCardSkeleton } from './AssetCard';
import TimeRangeToggle from '../TimeRangeToggle/TimeRangeToggle';
import { ASSETS, getAssetsByCategory } from '../../data/assets';
import './Dashboard.css';

const Dashboard = ({
    selectedCategory,
    timeRange,
    onTimeRangeChange,
    vulnerabilities,
    vulnCounts,
    stats,
    isLoading,
    loadingProgress,
    onAssetClick,
    selectedAsset
}) => {
    // Get assets for current category
    const assets = selectedCategory === 'All'
        ? ASSETS
        : getAssetsByCategory(selectedCategory);

    return (
        <main className="dashboard">
            <header className="dashboard-header">
                <div>
                    <h1 className="dashboard-title">
                        {selectedCategory === 'All' ? 'Security Dashboard' : selectedCategory}
                    </h1>
                    <p className="dashboard-subtitle">
                        Monitoring {assets.length} assets for vulnerabilities
                    </p>
                </div>
                <TimeRangeToggle value={timeRange} onChange={onTimeRangeChange} />
            </header>

            {/* Stats Grid */}
            <div className="stats-grid">
                <div className="stat-card total">
                    <div className="stat-card-label">Total Alerts</div>
                    <div className="stat-card-value">{stats?.total || 0}</div>
                </div>
                <div className="stat-card critical">
                    <div className="stat-card-label">Critical</div>
                    <div className="stat-card-value">{stats?.critical || 0}</div>
                </div>
                <div className="stat-card high">
                    <div className="stat-card-label">High</div>
                    <div className="stat-card-value">{stats?.high || 0}</div>
                </div>
                <div className="stat-card medium">
                    <div className="stat-card-label">Medium</div>
                    <div className="stat-card-value">{stats?.medium || 0}</div>
                </div>
                <div className="stat-card low">
                    <div className="stat-card-label">Low</div>
                    <div className="stat-card-value">{stats?.low || 0}</div>
                </div>
            </div>

            {/* Loading State */}
            {isLoading && (
                <div className="loading-container">
                    <div className="loading-spinner" />
                    <p className="loading-text">
                        Fetching vulnerabilities... {loadingProgress?.asset || ''}
                    </p>
                    {loadingProgress && (
                        <div className="loading-progress">
                            <div
                                className="loading-progress-bar"
                                style={{
                                    width: `${(loadingProgress.current / loadingProgress.total) * 100}%`
                                }}
                            />
                        </div>
                    )}
                </div>
            )}

            {/* Assets Grid */}
            {!isLoading && (
                <section className="assets-section">
                    <div className="section-header">
                        <h2 className="section-title">
                            <Shield />
                            Monitored Assets
                        </h2>
                    </div>

                    {assets.length === 0 ? (
                        <div className="empty-state">
                            <div className="empty-state-icon">
                                <AlertTriangle />
                            </div>
                            <h3 className="empty-state-title">No assets found</h3>
                            <p className="empty-state-text">
                                There are no assets in this category.
                            </p>
                        </div>
                    ) : (
                        <div className="assets-grid">
                            {assets.map(asset => (
                                <AssetCard
                                    key={asset.id}
                                    asset={asset}
                                    vulnCounts={vulnCounts?.[asset.id] || {}}
                                    onClick={onAssetClick}
                                    isSelected={selectedAsset?.id === asset.id}
                                />
                            ))}
                        </div>
                    )}
                </section>
            )}
        </main>
    );
};

export default Dashboard;
