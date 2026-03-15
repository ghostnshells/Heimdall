import React from 'react';
import { ChevronRight } from 'lucide-react';

const scoreClass = (score) => {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
};

const ChainCard = ({ chain, isExpanded, onToggle }) => {
    const uniqueAssets = [...new Set(chain.steps.map(s => s.asset))];
    const hasKEV = chain.steps.some(s => s.activelyExploited);
    const actors = [...new Set(chain.steps.flatMap(s => s.threatActors || []))];

    return (
        <div className="chain-card">
            <div className="chain-card-header" onClick={onToggle}>
                <div className={`chain-card-score ${scoreClass(chain.score)}`}>
                    {chain.score}
                </div>

                <div className="chain-card-body">
                    <div className="chain-card-flow">
                        {chain.stages.map((stage, i) => (
                            <React.Fragment key={`${chain.id}-${stage}-${i}`}>
                                {i > 0 && (
                                    <ChevronRight size={12} className="chain-flow-arrow" />
                                )}
                                <span className="chain-stage-pill">{stage}</span>
                            </React.Fragment>
                        ))}
                    </div>

                    <div className="chain-card-meta">
                        {uniqueAssets.map(asset => (
                            <span key={asset} className="chain-asset-tag">{asset}</span>
                        ))}
                        {hasKEV && <span className="chain-kev-tag">KEV</span>}
                        {actors.slice(0, 2).map(actor => (
                            <span key={actor} className="chain-actor-tag">{actor}</span>
                        ))}
                    </div>
                </div>

                <ChevronRight
                    size={16}
                    className={`chain-card-chevron ${isExpanded ? 'expanded' : ''}`}
                />
            </div>

            {isExpanded && (
                <div className="chain-card-detail">
                    {chain.steps.map((step, i) => (
                        <div key={`${chain.id}-step-${i}`} className="chain-step">
                            <div className="chain-step-stage">{step.stage}</div>
                            <div className="chain-step-info">
                                <div className="chain-step-cve">{step.cveId}</div>
                                <div className="chain-step-scores">
                                    <span>CVSS: {step.cvssScore.toFixed(1)}</span>
                                    <span>EPSS: {(step.epssScore * 100).toFixed(1)}%</span>
                                    <span>{step.asset}</span>
                                    {step.activelyExploited && <span style={{ color: 'var(--severity-critical)' }}>KEV</span>}
                                </div>
                                {step.description && (
                                    <div className="chain-step-desc">{step.description}</div>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
};

export default ChainCard;
