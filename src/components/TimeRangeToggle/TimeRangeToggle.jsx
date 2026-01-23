import React from 'react';
import { Calendar } from 'lucide-react';
import './TimeRangeToggle.css';

const TIME_RANGES = [
    { value: '24h', label: '24h' },
    { value: '7d', label: '7 days' },
    { value: '30d', label: '30 days' },
    { value: '90d', label: '90 days' },
    { value: '119d', label: '120 days' }  // Use 119 to stay within NVD API's 120-day limit
];

const TimeRangeToggle = ({ value, onChange }) => {
    return (
        <div className="time-range-toggle">
            <div className="time-range-label">
                <Calendar />
                <span>Range:</span>
            </div>
            {TIME_RANGES.map(range => (
                <button
                    key={range.value}
                    className={`time-range-option ${value === range.value ? 'active' : ''}`}
                    onClick={() => onChange(range.value)}
                >
                    {range.label}
                </button>
            ))}
        </div>
    );
};

export default TimeRangeToggle;
