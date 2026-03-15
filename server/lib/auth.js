// Authentication service — PostgreSQL-backed user management and JWT tokens

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from './db.js';
import { sendVerificationEmail, sendPasswordResetEmail } from './emailService.js';

if (!process.env.JWT_SECRET) {
    throw new Error('FATAL: JWT_SECRET environment variable is not set. Server cannot start without it.');
}
const JWT_SECRET = process.env.JWT_SECRET;
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY_SECONDS = 7 * 24 * 60 * 60; // 7 days

/**
 * Generate a secure random token, returning raw + SHA-256 hash
 */
export function generateSecureToken() {
    const raw = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    return { raw, hash };
}

/**
 * Create a new user
 */
export async function createUser(email, password) {
    const normalizedEmail = email.toLowerCase().trim();
    const passwordHash = await bcrypt.hash(password, 12);

    try {
        const { rows } = await pool.query(
            `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING email, created_at, email_verified`,
            [normalizedEmail, passwordHash]
        );
        return {
            email: rows[0].email,
            createdAt: rows[0].created_at.toISOString(),
            emailVerified: rows[0].email_verified
        };
    } catch (err) {
        if (err.code === '23505') { // unique_violation
            throw new Error('User already exists');
        }
        throw err;
    }
}

/**
 * Validate password for a user
 */
export async function validatePassword(email, password) {
    const normalizedEmail = email.toLowerCase().trim();
    const { rows } = await pool.query(
        `SELECT email, password_hash, created_at, email_verified FROM users WHERE email = $1`,
        [normalizedEmail]
    );

    if (rows.length === 0) {
        throw new Error('Invalid credentials');
    }

    const user = rows[0];

    // OAuth-only users have no password — can't log in with email/password
    if (!user.password_hash) {
        throw new Error('Invalid credentials');
    }

    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
        throw new Error('Invalid credentials');
    }

    return {
        email: user.email,
        createdAt: user.created_at.toISOString(),
        emailVerified: user.email_verified
    };
}

/**
 * Generate access + refresh token pair
 */
export function generateTokens(email) {
    const accessToken = jwt.sign(
        { email, type: 'access' },
        JWT_SECRET,
        { algorithm: 'HS256', expiresIn: ACCESS_TOKEN_EXPIRY }
    );

    const refreshToken = jwt.sign(
        { email, type: 'refresh' },
        JWT_SECRET,
        { algorithm: 'HS256', expiresIn: '7d' }
    );

    return { accessToken, refreshToken };
}

/**
 * Verify an access token
 */
export function verifyAccessToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        if (decoded.type !== 'access') {
            throw new Error('Invalid token type');
        }
        return decoded;
    } catch (error) {
        throw new Error('Invalid or expired token');
    }
}

/**
 * Verify a refresh token
 */
export function verifyRefreshToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        if (decoded.type !== 'refresh') {
            throw new Error('Invalid token type');
        }
        return decoded;
    } catch (error) {
        throw new Error('Invalid or expired refresh token');
    }
}

/**
 * Store refresh token in database (for revocation tracking)
 */
export async function storeRefreshToken(refreshToken, email) {
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_SECONDS * 1000);
    await pool.query(
        `INSERT INTO sessions (refresh_token, email, expires_at) VALUES ($1, $2, $3)`,
        [refreshToken, email, expiresAt]
    );
}

/**
 * Check if a refresh token is still valid (not revoked)
 */
export async function isRefreshTokenValid(refreshToken) {
    const { rows } = await pool.query(
        `SELECT email FROM sessions WHERE refresh_token = $1 AND expires_at > NOW()`,
        [refreshToken]
    );
    return rows.length ? rows[0].email : null;
}

/**
 * Revoke a refresh token
 */
export async function revokeRefreshToken(refreshToken) {
    await pool.query(
        `DELETE FROM sessions WHERE refresh_token = $1`,
        [refreshToken]
    );
}

/**
 * Get user info (without password hash)
 */
export async function getUser(email) {
    const normalizedEmail = email.toLowerCase().trim();
    const { rows } = await pool.query(
        `SELECT email, created_at, email_verified FROM users WHERE email = $1`,
        [normalizedEmail]
    );
    if (rows.length === 0) return null;
    return {
        email: rows[0].email,
        createdAt: rows[0].created_at.toISOString(),
        emailVerified: rows[0].email_verified
    };
}

/**
 * Find or create a user from an OAuth provider callback.
 * If the user already exists (by email), link the OAuth account.
 * OAuth users are auto-verified (provider already validated their email).
 */
export async function findOrCreateOAuthUser(provider, providerId, email, displayName, avatarUrl) {
    const normalizedEmail = email.toLowerCase().trim();

    // Check if this OAuth account is already linked
    const { rows: existing } = await pool.query(
        `SELECT email FROM oauth_accounts WHERE provider = $1 AND provider_id = $2`,
        [provider, providerId]
    );

    if (existing.length > 0) {
        // Already linked — return the user
        const user = await getUser(existing[0].email);
        return user;
    }

    // Check if user exists by email
    const { rows: users } = await pool.query(
        `SELECT email FROM users WHERE email = $1`,
        [normalizedEmail]
    );

    if (users.length === 0) {
        // Create new user (no password — OAuth-only)
        await pool.query(
            `INSERT INTO users (email, password_hash, email_verified) VALUES ($1, NULL, TRUE)`,
            [normalizedEmail]
        );
    } else {
        // Existing user — ensure email is verified (provider confirmed it)
        await pool.query(
            `UPDATE users SET email_verified = TRUE WHERE email = $1`,
            [normalizedEmail]
        );
    }

    // Link OAuth account
    await pool.query(
        `INSERT INTO oauth_accounts (provider, provider_id, email, display_name, avatar_url)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (provider, provider_id) DO UPDATE SET email = $3, display_name = $4, avatar_url = $5`,
        [provider, providerId, normalizedEmail, displayName || null, avatarUrl || null]
    );

    return await getUser(normalizedEmail);
}

/**
 * Request email verification — generates token, sends email
 */
export async function requestEmailVerification(email) {
    const normalizedEmail = email.toLowerCase().trim();

    // Delete any existing verification tokens for this email
    await pool.query(
        `DELETE FROM email_verification_tokens WHERE email = $1`,
        [normalizedEmail]
    );

    const { raw, hash } = generateSecureToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    await pool.query(
        `INSERT INTO email_verification_tokens (token_hash, email, expires_at) VALUES ($1, $2, $3)`,
        [hash, normalizedEmail, expiresAt]
    );

    await sendVerificationEmail(normalizedEmail, raw);
}

/**
 * Verify email with raw token from email link
 */
export async function verifyEmail(rawToken) {
    const hash = crypto.createHash('sha256').update(rawToken).digest('hex');

    const { rows } = await pool.query(
        `SELECT email FROM email_verification_tokens WHERE token_hash = $1 AND expires_at > NOW()`,
        [hash]
    );

    if (rows.length === 0) {
        throw new Error('Invalid or expired verification token');
    }

    const email = rows[0].email;

    await pool.query(
        `UPDATE users SET email_verified = TRUE WHERE email = $1`,
        [email]
    );

    await pool.query(
        `DELETE FROM email_verification_tokens WHERE email = $1`,
        [email]
    );

    return email;
}

/**
 * Request password reset — silent no-op if user not found (prevent enumeration)
 */
export async function requestPasswordReset(email) {
    const normalizedEmail = email.toLowerCase().trim();

    // Check if user exists and email is verified
    const { rows: users } = await pool.query(
        `SELECT email, email_verified FROM users WHERE email = $1`,
        [normalizedEmail]
    );

    if (users.length === 0 || !users[0].email_verified) {
        // Silent — don't reveal if user exists
        return;
    }

    // Rate limit: max 3 requests per hour
    const { rows: recent } = await pool.query(
        `SELECT COUNT(*) as cnt FROM password_reset_tokens
         WHERE email = $1 AND created_at > NOW() - INTERVAL '1 hour'`,
        [normalizedEmail]
    );

    if (parseInt(recent[0].cnt) >= 3) {
        throw new Error('Too many reset requests. Please try again later.');
    }

    const { raw, hash } = generateSecureToken();
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    await pool.query(
        `INSERT INTO password_reset_tokens (token_hash, email, expires_at) VALUES ($1, $2, $3)`,
        [hash, normalizedEmail, expiresAt]
    );

    await sendPasswordResetEmail(normalizedEmail, raw);
}

/**
 * Reset password using token from email
 */
export async function resetPassword(rawToken, newPassword) {
    const hash = crypto.createHash('sha256').update(rawToken).digest('hex');

    // Atomic: mark token as used and retrieve email in one query to prevent race conditions
    const { rows } = await pool.query(
        `UPDATE password_reset_tokens SET used = TRUE
         WHERE token_hash = $1 AND expires_at > NOW() AND used = FALSE
         RETURNING email`,
        [hash]
    );

    if (rows.length === 0) {
        throw new Error('Invalid or expired reset token');
    }

    const email = rows[0].email;
    const passwordHash = await bcrypt.hash(newPassword, 12);

    // Update password
    await pool.query(
        `UPDATE users SET password_hash = $1 WHERE email = $2`,
        [passwordHash, email]
    );

    // Invalidate all sessions (force re-login)
    await pool.query(
        `DELETE FROM sessions WHERE email = $1`,
        [email]
    );

    return email;
}
