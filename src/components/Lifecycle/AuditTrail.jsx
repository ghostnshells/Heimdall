import React, { useState, useEffect } from 'react';
import { History, ChevronDown, ChevronRight } from 'lucide-react';
import { getAuditTrail, getStatusInfo } from '../../services/lifecycleService';
import './Lifecycle.css';

const AuditTrail = ({ cveId, isAuthenticated }) => {
    const [trail, setTrail] = useState([]);
    const [isExpanded, setIsExpanded] = useState(false);
    const [isLoading, setIsLoading] = useState(false);

    useEffect(() => {
        if (isExpanded && isAuthenticated && trail.length === 0) {
            loadTrail();
        }
    }, [isExpanded, isAuthenticated]);

    const loadTrail = async () => {
        setIsLoading(true);
        try {
            const data = await getAuditTrail(cveId);
            setTrail(data);
        } catch (error) {
            console.error('Failed to load audit trail:', error);
        } finally {
            setIsLoading(false);
        }
    };

    if (!isAuthenticated) return null;

    const toggleExpand = (e) => {
        e.stopPropagation();
        setIsExpanded(!isExpanded);
    };

    const formatDate = (dateString) => {
        return new Date(dateString).toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    return (
        <div className="audit-trail">
            <div className="audit-trail-header" onClick={toggleExpand}>
                {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                <History size={14} />
                <span>Audit Trail</span>
                {trail.length > 0 && <span className="audit-trail-count">{trail.length}</span>}
            </div>

            {isExpanded && (
                <div className="audit-trail-content">
                    {isLoading ? (
                        <div className="audit-trail-loading">Loading...</div>
                    ) : trail.length === 0 ? (
                        <div className="audit-trail-empty">No status changes recorded</div>
                    ) : (
                        <div className="audit-trail-timeline">
                            {trail.map((entry, idx) => {
                                const fromInfo = getStatusInfo(entry.from);
                                const toInfo = getStatusInfo(entry.to);
                                return (
                                    <div key={idx} className="audit-trail-entry">
                                        <div className="audit-trail-dot" style={{ background: toInfo.color }} />
                                        <div className="audit-trail-entry-content">
                                            <div className="audit-trail-change">
                                                <span className="audit-status" style={{ color: fromInfo.color }}>{fromInfo.label}</span>
                                                <span className="audit-arrow">&rarr;</span>
                                                <span className="audit-status" style={{ color: toInfo.color }}>{toInfo.label}</span>
                                            </div>
                                            <div className="audit-trail-time">{formatDate(entry.timestamp)}</div>
                                            {entry.notes && <div className="audit-trail-notes">{entry.notes}</div>}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default AuditTrail;
