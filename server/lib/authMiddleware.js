// Authentication middleware for protected API routes

import { verifyAccessToken } from './auth.js';

/**
 * Middleware wrapper that verifies JWT Bearer token
 * Usage: wrap your handler — requireAuth(handler)
 */
export function requireAuth(handler) {
    return async (req, res) => {
        const authHeader = req.headers['authorization'];

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        const token = authHeader.slice(7);

        try {
            const decoded = verifyAccessToken(token);
            req.user = { email: decoded.email };
            return handler(req, res);
        } catch (error) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
    };
}
