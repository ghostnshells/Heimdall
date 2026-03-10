// POST /api/auth/login — Authenticate user and return tokens

import { validatePassword, generateTokens, storeRefreshToken } from '../../server/lib/auth.js';
import { serializeRefreshTokenCookie, clearRefreshTokenCookie } from './_cookies.js';

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

        if (!user.emailVerified) {
            return res.status(403).json({ error: 'Please verify your email before logging in.', code: 'EMAIL_NOT_VERIFIED' });
        }

        const tokens = generateTokens(user.email);
        await storeRefreshToken(tokens.refreshToken, user.email);

        res.setHeader('Set-Cookie', serializeRefreshTokenCookie(tokens.refreshToken));
        res.json({
            success: true,
            user,
            accessToken: tokens.accessToken
        });
    } catch (error) {
        if (error.message === 'Invalid credentials') {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
