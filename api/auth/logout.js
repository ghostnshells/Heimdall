// POST /api/auth/logout — Revoke refresh token

import { revokeRefreshToken } from '../../server/lib/auth.js';
import { parseCookies, clearRefreshTokenCookie } from './_cookies.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const cookies = parseCookies(req);
        const refreshToken = cookies.refreshToken;

        if (refreshToken) {
            await revokeRefreshToken(refreshToken);
        }

        res.setHeader('Set-Cookie', clearRefreshTokenCookie());
        res.json({ success: true });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
