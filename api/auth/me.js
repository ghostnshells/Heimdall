// GET /api/auth/me — Return current authenticated user

import { requireAuth } from '../../server/lib/authMiddleware.js';
import { getUser } from '../../server/lib/auth.js';

export default requireAuth(async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const user = await getUser(req.user.email);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ success: true, user });
    } catch (error) {
        console.error('Me error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});
