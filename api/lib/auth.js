// Authentication service — Redis-backed user management and JWT tokens

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { redis } from './redis.js';

const JWT_SECRET = process.env.JWT_SECRET || 'heimdall-dev-secret-change-me';
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY_SECONDS = 7 * 24 * 60 * 60; // 7 days

/**
 * Create a new user
 */
export async function createUser(email, password) {
    const normalizedEmail = email.toLowerCase().trim();

    // Check if user already exists
    const existing = await redis.get(`user:${normalizedEmail}`);
    if (existing) {
        throw new Error('User already exists');
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = {
        email: normalizedEmail,
        passwordHash,
        createdAt: new Date().toISOString()
    };

    await redis.set(`user:${normalizedEmail}`, user);

    return { email: normalizedEmail, createdAt: user.createdAt };
}

/**
 * Validate password for a user
 */
export async function validatePassword(email, password) {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await redis.get(`user:${normalizedEmail}`);

    if (!user) {
        throw new Error('Invalid credentials');
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
        throw new Error('Invalid credentials');
    }

    return { email: user.email, createdAt: user.createdAt };
}

/**
 * Generate access + refresh token pair
 */
export function generateTokens(email) {
    const accessToken = jwt.sign(
        { email, type: 'access' },
        JWT_SECRET,
        { expiresIn: ACCESS_TOKEN_EXPIRY }
    );

    const refreshToken = jwt.sign(
        { email, type: 'refresh' },
        JWT_SECRET,
        { expiresIn: '7d' }
    );

    return { accessToken, refreshToken };
}

/**
 * Verify an access token
 */
export function verifyAccessToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
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
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.type !== 'refresh') {
            throw new Error('Invalid token type');
        }
        return decoded;
    } catch (error) {
        throw new Error('Invalid or expired refresh token');
    }
}

/**
 * Store refresh token in Redis (for revocation tracking)
 */
export async function storeRefreshToken(refreshToken, email) {
    await redis.set(
        `user:session:${refreshToken}`,
        email,
        { ex: REFRESH_TOKEN_EXPIRY_SECONDS }
    );
}

/**
 * Check if a refresh token is still valid (not revoked)
 */
export async function isRefreshTokenValid(refreshToken) {
    const email = await redis.get(`user:session:${refreshToken}`);
    return email || null;
}

/**
 * Revoke a refresh token
 */
export async function revokeRefreshToken(refreshToken) {
    await redis.del(`user:session:${refreshToken}`);
}

/**
 * Get user info (without password hash)
 */
export async function getUser(email) {
    const normalizedEmail = email.toLowerCase().trim();
    const user = await redis.get(`user:${normalizedEmail}`);
    if (!user) return null;
    return { email: user.email, createdAt: user.createdAt };
}
