// GET/PUT /api/lifecycle/status — Get or update vulnerability status

import { requireAuth } from '../../server/lib/authMiddleware.js';
import { getVulnStatus, setVulnStatus } from '../../server/lib/lifecycleService.js';
import { validateCveId } from '../../server/lib/validation.js';

export default requireAuth(async function handler(req, res) {
    const { cveId } = req.query;

    if (!cveId) {
        return res.status(400).json({ error: 'cveId query parameter is required' });
    }
    if (!validateCveId(cveId)) {
        return res.status(400).json({ error: 'Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN' });
    }

    const userId = req.user.email;

    if (req.method === 'GET') {
        try {
            const status = await getVulnStatus(userId, cveId);
            return res.json({ success: true, data: status });
        } catch (error) {
            console.error('Get status error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    if (req.method === 'PUT') {
        try {
            const { status, notes } = req.body || {};

            if (!status) {
                return res.status(400).json({ error: 'status is required' });
            }

            const result = await setVulnStatus(userId, cveId, status, notes || '');
            return res.json({ success: true, data: result });
        } catch (error) {
            if (error.message.includes('Invalid status')) {
                return res.status(400).json({ error: error.message });
            }
            console.error('Set status error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        }
    }

    return res.status(405).json({ error: 'Method not allowed' });
});
