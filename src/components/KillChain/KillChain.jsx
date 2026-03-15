import React, { useState, useEffect, useCallback, useRef } from 'react';
import { RefreshCw, AlertTriangle, Shield } from 'lucide-react';
import { fetchKillChains, clearKillChainCache } from '../../services/killChainService';
import StageBar from './StageBar';
import ChainCard from './ChainCard';
import BreakTheChain from './BreakTheChain';
import './KillChain.css';

const AUTO_REFRESH_INTERVAL = 5 * 60 * 1000; // 5 minutes

const KillChain = ({ timeRange = '7d' }) => {
    const [data, setData] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState(null);
    const [expandedChain, setExpandedChain] = useState(null);
    const intervalRef = useRef(null);

    const loadData = useCallback(async (forceRefresh = false) => {
        setIsLoading(true);
        setError(null);
        try {
            const result = await fetchKillChains(timeRange, forceRefresh);
            setData(result);
        } catch (err) {
            console.error('[KillChain] Fetch error:', err);
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    }, [timeRange]);

    useEffect(() => {
        loadData();
    }, [loadData]);

    useEffect(() => {
        intervalRef.current = setInterval(() => {
            loadData();
        }, AUTO_REFRESH_INTERVAL);
        return () => clearInterval(intervalRef.current);
    }, [loadData]);

    const handleRefresh = () => {
        clearKillChainCache();
        loadData(true);
    };

    const toggleChain = (chainId) => {
        setExpandedChain(prev => prev === chainId ? null : chainId);
    };

    // Loading state
    if (isLoading && !data) {
        return (
            <div className="killchain">
                <div className="killchain-header">
                    <div className="killchain-header-left">
                        <h1>Kill Chain</h1>
                        <p>Attack chain analysis across your infrastructure</p>
                    </div>
                </div>
                <div className="killchain-loading">
                    <div className="killchain-loading-spinner" />
                    <p>Analyzing attack chains...</p>
                </div>
            </div>
        );
    }

    // Error state
    if (error && !data) {
        return (
            <div className="killchain">
                <div className="killchain-header">
                    <div className="killchain-header-left">
                        <h1>Kill Chain</h1>
                        <p>Attack chain analysis across your infrastructure</p>
                    </div>
                </div>
                <div className="killchain-error">
                    <AlertTriangle size={32} className="killchain-error-icon" />
                    <h3>Failed to load kill chain data</h3>
                    <p>{error}</p>
                    <button onClick={handleRefresh}>Try Again</button>
                </div>
            </div>
        );
    }

    const { chains = [], breakRecommendations = [], stageDistribution = {}, summary = {} } = data || {};

    // Empty state
    if (chains.length === 0) {
        return (
            <div className="killchain">
                <div className="killchain-header">
                    <div className="killchain-header-left">
                        <h1>Kill Chain</h1>
                        <p>Attack chain analysis across your infrastructure</p>
                    </div>
                    <button className="killchain-refresh-btn" onClick={handleRefresh} disabled={isLoading}>
                        <RefreshCw size={14} className={isLoading ? 'spinning' : ''} />
                        {isLoading ? 'Refreshing...' : 'Refresh'}
                    </button>
                </div>
                <div className="killchain-empty">
                    <Shield size={40} />
                    <h3>No attack chains detected</h3>
                    <p>
                        No multi-stage attack paths were found spanning 3 or more kill chain stages.
                        This could mean your current vulnerabilities don't form exploitable chains,
                        or try expanding the time range.
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="killchain">
            <div className="killchain-header">
                <div className="killchain-header-left">
                    <h1>Kill Chain</h1>
                    <p>Attack chain analysis across your infrastructure</p>
                </div>
                <button className="killchain-refresh-btn" onClick={handleRefresh} disabled={isLoading}>
                    <RefreshCw size={14} className={isLoading ? 'spinning' : ''} />
                    {isLoading ? 'Refreshing...' : 'Refresh'}
                </button>
            </div>

            {/* Summary Stats */}
            <div className="killchain-summary">
                <div className="killchain-stat">
                    <div className="killchain-stat-label">Attack Chains</div>
                    <div className="killchain-stat-value">{summary.totalChains}</div>
                </div>
                <div className="killchain-stat">
                    <div className="killchain-stat-label">Critical Chains</div>
                    <div className={`killchain-stat-value ${summary.criticalChains > 0 ? 'critical' : ''}`}>
                        {summary.criticalChains}
                    </div>
                </div>
                <div className="killchain-stat">
                    <div className="killchain-stat-label">Avg Risk Score</div>
                    <div className="killchain-stat-value">{summary.avgScore}</div>
                </div>
                <div className="killchain-stat">
                    <div className="killchain-stat-label">Stage Coverage</div>
                    <div className="killchain-stat-value">
                        {summary.coveredStages}/{summary.totalStages}
                    </div>
                </div>
            </div>

            {/* Stage Distribution */}
            <div className="killchain-section">
                <div className="killchain-section-title">Stage Distribution</div>
                <StageBar distribution={stageDistribution} />
            </div>

            {/* Attack Chains */}
            <div className="killchain-section">
                <div className="killchain-section-title">
                    Attack Chains ({chains.length})
                </div>
                {chains.map(chain => (
                    <ChainCard
                        key={chain.id}
                        chain={chain}
                        isExpanded={expandedChain === chain.id}
                        onToggle={() => toggleChain(chain.id)}
                    />
                ))}
            </div>

            {/* Break the Chain */}
            {breakRecommendations.length > 0 && (
                <div className="killchain-section">
                    <div className="killchain-section-title">
                        Break the Chain — Priority Patching
                    </div>
                    <BreakTheChain recommendations={breakRecommendations} />
                </div>
            )}
        </div>
    );
};

export default KillChain;
