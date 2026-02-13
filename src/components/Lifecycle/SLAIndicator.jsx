import React from 'react';
import { Clock, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { getSLADaysRemaining, isSLABreached } from '../../services/lifecycleService';
import './Lifecycle.css';

const SLAIndicator = ({ publishedDate, severity, status, slaConfig }) => {
    if (!publishedDate || !severity) return null;

    const terminalStatuses = ['patched', 'mitigated', 'accepted_risk', 'false_positive'];
    if (terminalStatuses.includes(status)) {
        return (
            <span className="sla-indicator sla-resolved" title="Resolved">
                <CheckCircle2 size={12} />
                Resolved
            </span>
        );
    }

    const daysRemaining = getSLADaysRemaining(publishedDate, severity, slaConfig);
    const breached = isSLABreached(publishedDate, severity, status, slaConfig);

    if (breached) {
        return (
            <span className="sla-indicator sla-breached" title={`SLA breached ${Math.abs(daysRemaining)} days ago`}>
                <AlertTriangle size={12} />
                SLA Breached ({Math.abs(daysRemaining)}d overdue)
            </span>
        );
    }

    if (daysRemaining <= 7) {
        return (
            <span className="sla-indicator sla-urgent" title={`${daysRemaining} days until SLA breach`}>
                <Clock size={12} />
                {daysRemaining}d remaining
            </span>
        );
    }

    return (
        <span className="sla-indicator sla-ok" title={`${daysRemaining} days until SLA breach`}>
            <Clock size={12} />
            {daysRemaining}d remaining
        </span>
    );
};

export default SLAIndicator;
