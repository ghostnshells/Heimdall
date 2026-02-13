// POST /api/auth/refresh — Exchange refresh token for new token pair

import {
    verifyRefreshToken,
    isRefreshTokenValid,
    revokeRefreshToken,
    generateTokens,
    storeRefreshToken
} from '../../server/lib/auth.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { refreshToken } = req.body || {};

        if (!refreshToken) {
            return res.status(400).json({ error: 'Refresh token is required' });
        }

        // Verify the token signature
        const decoded = verifyRefreshToken(refreshToken);

        // Check if the token hasn't been revoked
        const storedEmail = await isRefreshTokenValid(refreshToken);
        if (!storedEmail) {
            return res.status(401).json({ error: 'Refresh token has been revoked' });
        }

        // Revoke the old refresh token (rotation)
        await revokeRefreshToken(refreshToken);

        // Generate new token pair
        const tokens = generateTokens(decoded.email);
        await storeRefreshToken(tokens.refreshToken, decoded.email);

        res.json({
            success: true,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        });
    } catch (error) {
        if (error.message.includes('Invalid') || error.message.includes('expired')) {
            return res.status(401).json({ error: 'Invalid or expired refresh token' });
        }
        console.error('Refresh error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
