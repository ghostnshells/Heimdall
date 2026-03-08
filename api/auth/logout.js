// POST /api/auth/logout — Revoke refresh token

import { revokeRefreshToken } from '../../server/lib/auth.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { refreshToken } = req.body || {};

        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token is required' });
        }

        await revokeRefreshToken(refreshToken);
        res.json({ success: true });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
