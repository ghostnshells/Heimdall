// GET /api/lifecycle/audit — Get audit trail for a CVE

import { requireAuth } from '../../server/lib/authMiddleware.js';
import { getAuditTrail } from '../../server/lib/lifecycleService.js';
import { validateCveId } from '../../server/lib/validation.js';

export default requireAuth(async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { cveId } = req.query;

    if (!cveId) {
        return res.status(400).json({ error: 'cveId query parameter is required' });
    }
    if (!validateCveId(cveId)) {
        return res.status(400).json({ error: 'Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN' });
    }

    try {
        const trail = await getAuditTrail(req.user.email, cveId);
        res.json({ success: true, data: trail });
    } catch (error) {
        console.error('Audit trail error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
