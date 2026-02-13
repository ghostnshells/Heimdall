// GET /api/lifecycle/audit — Get audit trail for a CVE

import { requireAuth } from '../lib/authMiddleware.js';
import { getAuditTrail } from '../lib/lifecycleService.js';

export default requireAuth(async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    const { cveId } = req.query;

    if (!cveId) {
        return res.status(400).json({ error: 'cveId query parameter is required' });
    }

    try {
        const trail = await getAuditTrail(req.user.email, cveId);
        res.json({ success: true, data: trail });
    } catch (error) {
        console.error('Audit trail error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
