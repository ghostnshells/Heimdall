// POST /api/auth/signup — Create new user account

import { createUser, generateTokens, storeRefreshToken } from '../../server/lib/auth.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { email, password } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const user = await createUser(email, password);
        const tokens = generateTokens(user.email);
        await storeRefreshToken(tokens.refreshToken, user.email);

        res.status(201).json({
            success: true,
            user,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        });
    } catch (error) {
        if (error.message === 'User already exists') {
            return res.status(409).json({ error: 'User already exists' });
        }
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
