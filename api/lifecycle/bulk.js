// POST /api/lifecycle/bulk — Bulk status update for multiple CVEs

import { requireAuth } from '../lib/authMiddleware.js';
import { setBulkStatus } from '../lib/lifecycleService.js';

export default requireAuth(async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { cveIds, status, notes } = req.body || {};

        if (!cveIds || !Array.isArray(cveIds) || cveIds.length === 0) {
            return res.status(400).json({ error: 'cveIds array is required' });
        }

        if (!status) {
            return res.status(400).json({ error: 'status is required' });
        }

        if (cveIds.length > 100) {
            return res.status(400).json({ error: 'Maximum 100 CVEs per bulk update' });
        }

        const results = await setBulkStatus(req.user.email, cveIds, status, notes || '');
        res.json({ success: true, data: results, count: results.length });
    } catch (error) {
        if (error.message.includes('Invalid status')) {
            return res.status(400).json({ error: error.message });
        }
        console.error('Bulk update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
