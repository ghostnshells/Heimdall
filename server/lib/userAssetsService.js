// User asset customization service

import pool from './db.js';
import { ASSETS } from './assets.js';

const VALID_ASSET_IDS = new Set(ASSETS.map(a => a.id));

/**
 * Get user's selected asset IDs, or null if no preferences set (= show all)
 */
export async function getUserAssets(email) {
    const { rows } = await pool.query(
        `SELECT asset_id FROM user_assets WHERE user_email = $1 ORDER BY created_at`,
        [email]
    );
    if (rows.length === 0) return null; // No preferences = show all
    return rows.map(r => r.asset_id);
}

/**
 * Set user's selected assets (replaces all previous selections)
 */
export async function setUserAssets(email, assetIds) {
    // Validate all IDs
    const invalid = assetIds.filter(id => !VALID_ASSET_IDS.has(id));
    if (invalid.length > 0) {
        throw new Error(`Invalid asset IDs: ${invalid.join(', ')}`);
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query(`DELETE FROM user_assets WHERE user_email = $1`, [email]);

        if (assetIds.length > 0) {
            const values = assetIds.map((id, i) => `($1, $${i + 2})`).join(', ');
            await client.query(
                `INSERT INTO user_assets (user_email, asset_id) VALUES ${values}`,
                [email, ...assetIds]
            );
        }

        await client.query('COMMIT');
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }

    return assetIds;
}
