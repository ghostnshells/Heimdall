// POST /api/auth/signup — Create new user account

import { createUser, generateTokens, storeRefreshToken } from '../../server/lib/auth.js';
import { validatePasswordStrength } from '../../server/lib/validation.js';

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const { email, password } = req.body || {};

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const pwCheck = validatePasswordStrength(password);
        if (!pwCheck.valid) {
            return res.status(400).json({ error: pwCheck.error });
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
            return res.status(400).json({ error: 'Could not create account. Please try again or use a different email.' });
        }
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}
