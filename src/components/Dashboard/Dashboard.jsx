import React from 'react';
import { Shield, AlertTriangle, CheckCircle2, Building2 } from 'lucide-react';
import AssetCard, { AssetCardSkeleton } from './AssetCard';
import TimeRangeToggle from '../TimeRangeToggle/TimeRangeToggle';
import {
    ASSETS,
    getAssetsByCategory,
    getAssetsByVendorGroup,
    getAssetsByVendorAndSubcategory,
    getSubcategoriesForVendor
} from '../../data/assets';
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
    selectedAsset,
    viewMode = 'category',
    selectedVendor,
    selectedSubcategory
}) => {
    // Get assets based on view mode
    const getFilteredAssets = () => {
        if (viewMode === 'vendor') {
            if (selectedSubcategory && selectedVendor) {
                return getAssetsByVendorAndSubcategory(selectedVendor, selectedSubcategory);
            }
            if (selectedVendor) {
                return getAssetsByVendorGroup(selectedVendor);
            }
            return ASSETS;
        }
        // Category view (default)
        return selectedCategory === 'All'
            ? ASSETS
            : getAssetsByCategory(selectedCategory);
    };

    const assets = getFilteredAssets();

    // Get title based on view mode and selection
    const getTitle = () => {
        if (viewMode === 'vendor') {
            if (selectedSubcategory && selectedVendor) {
                return `${selectedVendor} - ${selectedSubcategory}`;
            }
            if (selectedVendor) {
                return selectedVendor;
            }
            return 'All Vendors';
        }
        return selectedCategory === 'All' ? 'Security Dashboard' : selectedCategory;
    };

    // Group assets by subcategory when viewing a vendor (for better organization)
    const getGroupedAssets = () => {
        if (viewMode === 'vendor' && selectedVendor && !selectedSubcategory) {
            const subcategories = getSubcategoriesForVendor(selectedVendor);
            if (subcategories.length > 1) {
                return subcategories.map(subcat => ({
                    name: subcat,
                    assets: getAssetsByVendorAndSubcategory(selectedVendor, subcat)
                }));
            }
        }
        return null;
    };

    const groupedAssets = getGroupedAssets();

    return (
        <main className="dashboard">
            <header className="dashboard-header">
                <div>
                    <h1 className="dashboard-title">
                        {viewMode === 'vendor' && selectedVendor && (
                            <Building2 className="title-icon" />
                        )}
                        {getTitle()}
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
                    {/* Grouped by subcategory (vendor view with vendor selected) */}
                    {groupedAssets ? (
                        <>
                            {groupedAssets.map(group => (
                                <div key={group.name} className="asset-group">
                                    <div className="section-header">
                                        <h2 className="section-title subcategory-title">
                                            {group.name}
                                            <span className="asset-count">({group.assets.length})</span>
                                        </h2>
                                    </div>
                                    <div className="assets-grid">
                                        {group.assets.map(asset => (
                                            <AssetCard
                                                key={asset.id}
                                                asset={asset}
                                                vulnCounts={vulnCounts?.[asset.id] || {}}
                                                onClick={onAssetClick}
                                                isSelected={selectedAsset?.id === asset.id}
                                            />
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </>
                    ) : (
                        <>
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
                                        There are no assets in this {viewMode === 'vendor' ? 'vendor group' : 'category'}.
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
                        </>
                    )}
                </section>
            )}
        </main>
    );
};

export default Dashboard;
