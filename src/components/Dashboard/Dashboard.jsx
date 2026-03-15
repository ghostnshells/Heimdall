import React, { useMemo } from 'react';
import { Shield, AlertTriangle, CheckCircle2, Clock } from 'lucide-react';
import AssetCard, { AssetCardSkeleton } from './AssetCard';
import TimeRangeToggle from '../TimeRangeToggle/TimeRangeToggle';
import VulnerabilityChart from './VulnerabilityChart';
import { ASSETS } from '../../data/assets';
import { isSLABreached, getSLADaysRemaining } from '../../services/lifecycleService';
import './Dashboard.css';

const SLASummary = ({ vulnerabilities, vulnStatuses, slaConfig }) => {
    const summary = useMemo(() => {
        let breached = 0;
        let approaching = 0;
        let acknowledged = 0;

        vulnerabilities.forEach(vuln => {
            const status = vulnStatuses[vuln.id]?.status || 'new';
            const terminalStatuses = ['patched', 'mitigated', 'accepted_risk', 'false_positive'];
            if (terminalStatuses.includes(status)) return;

            if (isSLABreached(vuln.published, vuln.severity, status, slaConfig)) {
                breached++;
            } else {
                const daysLeft = getSLADaysRemaining(vuln.published, vuln.severity, slaConfig);
                if (daysLeft <= 7) approaching++;
            }

            if (status === 'acknowledged' || status === 'in_progress') {
                acknowledged++;
            }
        });

        return { breached, approaching, acknowledged };
    }, [vulnerabilities, vulnStatuses, slaConfig]);

    if (summary.breached === 0 && summary.approaching === 0 && summary.acknowledged === 0) return null;

    return (
        <div className="sla-summary-row">
            {summary.breached > 0 && (
                <div className="sla-summary-card breached">
                    <AlertTriangle size={16} />
                    <div>
                        <div className="sla-summary-value">{summary.breached}</div>
                        <div className="sla-summary-label">SLA Breached</div>
                    </div>
                </div>
            )}
            {summary.approaching > 0 && (
                <div className="sla-summary-card approaching">
                    <Clock size={16} />
                    <div>
                        <div className="sla-summary-value">{summary.approaching}</div>
                        <div className="sla-summary-label">Approaching Deadline</div>
                    </div>
                </div>
            )}
            {summary.acknowledged > 0 && (
                <div className="sla-summary-card acknowledged">
                    <CheckCircle2 size={16} />
                    <div>
                        <div className="sla-summary-value">{summary.acknowledged}</div>
                        <div className="sla-summary-label">In Progress</div>
                    </div>
                </div>
            )}
        </div>
    );
};

const Dashboard = ({
    timeRange,
    onTimeRangeChange,
    vulnerabilities,
    vulnCounts,
    stats,
    isLoading,
    loadingProgress,
    onAssetClick,
    selectedAsset,
    isAuthenticated = false,
    vulnStatuses = {},
    slaConfig,
    userAssets
}) => {
    // Get assets filtered by user's selected assets
    const getFilteredAssets = () => {
        if (userAssets) {
            const allowedSet = new Set(userAssets);
            return ASSETS.filter(a => allowedSet.has(a.id));
        }
        return ASSETS;
    };

    const assets = getFilteredAssets();

    return (
        <main className="dashboard">
            <header className="dashboard-header">
                <div>
                    <h1 className="dashboard-title">
                        Security Dashboard
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

            {/* SLA Summary (only when authenticated) */}
            {isAuthenticated && vulnerabilities?.all && slaConfig && (
                <SLASummary vulnerabilities={vulnerabilities.all} vulnStatuses={vulnStatuses} slaConfig={slaConfig} />
            )}

            {/* Vulnerability Timeline Chart */}
            {!isLoading && vulnerabilities && (
                <VulnerabilityChart vulnerabilities={vulnerabilities} timeRange={timeRange} />
            )}

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
                                There are no monitored assets.
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
