import React from 'react';

const BreakTheChain = ({ recommendations = [] }) => {
    if (recommendations.length === 0) return null;

    const priorityClass = (p) => {
        if (p === 1) return 'p1';
        if (p === 2) return 'p2';
        if (p === 3) return 'p3';
        return 'rest';
    };

    return (
        <div className="break-table-wrapper">
            <table className="break-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>CVE ID</th>
                        <th>Asset</th>
                        <th>Stage</th>
                        <th>Chains Disrupted</th>
                        <th>Risk Reduction</th>
                    </tr>
                </thead>
                <tbody>
                    {recommendations.map((rec) => (
                        <tr key={rec.cveId}>
                            <td>
                                <span className={`break-priority ${priorityClass(rec.priority)}`}>
                                    {rec.priority}
                                </span>
                            </td>
                            <td className="break-cve">{rec.cveId}</td>
                            <td>{rec.asset}</td>
                            <td>{rec.stage}</td>
                            <td className="break-chains-disrupted">{rec.chainsDisrupted}</td>
                            <td className="break-risk-reduction">{rec.totalRiskReduction}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

export default BreakTheChain;
