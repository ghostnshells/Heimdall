// POST /api/auth/login — Authenticate user and return tokens

import { validatePassword, generateTokens, storeRefreshToken } from '../../server/lib/auth.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { email, password } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const user = await validatePassword(email, password);
        const tokens = generateTokens(user.email);
        await storeRefreshToken(tokens.refreshToken, user.email);

        res.json({
            success: true,
            user,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        });
    } catch (error) {
        if (error.message === 'Invalid credentials') {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
