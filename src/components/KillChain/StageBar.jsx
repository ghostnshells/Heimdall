import React from 'react';

const STAGE_LABELS = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Priv Esc',
    'Def Evasion',
    'Cred Access',
    'Lateral Mvmt',
    'Collection',
    'Exfiltration',
    'Impact',
];

const STAGE_KEYS = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Lateral Movement',
    'Collection',
    'Exfiltration',
    'Impact',
];

const StageBar = ({ distribution = {} }) => {
    const maxCount = Math.max(1, ...Object.values(distribution));

    return (
        <div className="stage-bar">
            {STAGE_KEYS.map((key, i) => {
                const count = distribution[key] || 0;
                const pct = (count / maxCount) * 100;
                const isZero = count === 0;

                return (
                    <div key={key} className="stage-bar-item">
                        <div className="stage-bar-fill-wrapper">
                            <div
                                className={`stage-bar-fill ${isZero ? 'zero' : ''}`}
                                style={{ height: isZero ? '2px' : `${Math.max(8, pct)}%` }}
                            />
                        </div>
                        <span className={`stage-bar-count ${isZero ? 'zero' : ''}`}>
                            {count}
                        </span>
                        <span className={`stage-bar-label ${isZero ? 'zero' : ''}`}>
                            {STAGE_LABELS[i]}
                        </span>
                    </div>
                );
            })}
        </div>
    );
};

export default StageBar;
