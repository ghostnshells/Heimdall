import React, { useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { STATUSES, getStatusInfo, setVulnStatus } from '../../services/lifecycleService';
import './Lifecycle.css';

const StatusBadge = ({ cveId, currentStatus = 'new', onStatusChange, isAuthenticated }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [isUpdating, setIsUpdating] = useState(false);
    const statusInfo = getStatusInfo(currentStatus);

    const handleStatusChange = async (newStatus, e) => {
        e.stopPropagation();
        if (newStatus === currentStatus || !isAuthenticated) return;

        setIsUpdating(true);
        try {
            await setVulnStatus(cveId, newStatus);
            onStatusChange?.(cveId, newStatus);
        } catch (error) {
            console.error('Failed to update status:', error);
        } finally {
            setIsUpdating(false);
            setIsOpen(false);
        }
    };

    const toggleDropdown = (e) => {
        e.stopPropagation();
        if (isAuthenticated) {
            setIsOpen(!isOpen);
        }
    };

    return (
        <div className="status-badge-container">
            <button
                className={`status-badge status-${currentStatus}`}
                onClick={toggleDropdown}
                disabled={!isAuthenticated || isUpdating}
                style={{ '--status-color': statusInfo.color }}
                title={isAuthenticated ? 'Click to change status' : 'Sign in to change status'}
            >
                <span className="status-dot" />
                {isUpdating ? 'Updating...' : statusInfo.label}
                {isAuthenticated && <ChevronDown size={12} />}
            </button>

            {isOpen && (
                <div className="status-dropdown" onClick={(e) => e.stopPropagation()}>
                    {STATUSES.map(status => (
                        <button
                            key={status.value}
                            className={`status-option ${status.value === currentStatus ? 'active' : ''}`}
                            onClick={(e) => handleStatusChange(status.value, e)}
                            style={{ '--status-color': status.color }}
                        >
                            <span className="status-dot" />
                            {status.label}
                        </button>
                    ))}
                </div>
            )}
        </div>
    );
};

export default StatusBadge;
