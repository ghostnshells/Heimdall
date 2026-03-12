// Frontend authentication service
// Handles token storage, auto-refresh, and authenticated API calls
// Access token: in-memory only (module-scoped variable)
// Refresh token: httpOnly cookie (managed by server, invisible to JS)
// User info: localStorage (non-sensitive display data)

const AUTH_API = '/api/auth';
const USER_KEY = 'panoptes_user';

// In-memory access token — lost on page reload, restored via silent refresh
let accessToken = null;

/**
 * Get stored access token (from memory)
 */
export function getAccessToken() {
    return accessToken;
}

/**
 * Get stored user info
 */
export function getStoredUser() {
    try {
        const user = localStorage.getItem(USER_KEY);
        return user ? JSON.parse(user) : null;
    } catch {
        return null;
    }
}

/**
 * Store access token and user info
 */
export function storeAuth(token, user) {
    accessToken = token;
    if (user) {
        localStorage.setItem(USER_KEY, JSON.stringify(user));
    }
}

/**
 * Update stored user data (e.g. after email verification)
 */
export function updateStoredUser(updates) {
    const current = getStoredUser();
    if (current) {
        localStorage.setItem(USER_KEY, JSON.stringify({ ...current, ...updates }));
    }
}

/**
 * Clear all auth data
 */
export function clearAuth() {
    accessToken = null;
    localStorage.removeItem(USER_KEY);
}

/**
 * Check if user is authenticated (has access token in memory)
 */
export function isAuthenticated() {
    return !!accessToken;
}

/**
 * Sign up a new user
 */
export async function signup(email, password) {
    const response = await fetch(`${AUTH_API}/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || 'Signup failed');
    }

    storeAuth(data.accessToken, data.user);
    return data.user;
}

/**
 * Log in with email and password
 */
export async function login(email, password) {
    const response = await fetch(`${AUTH_API}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || 'Login failed');
    }

    storeAuth(data.accessToken, data.user);
    return data.user;
}

/**
 * Refresh the access token using the httpOnly refresh token cookie
 */
export async function refreshTokens() {
    const response = await fetch(`${AUTH_API}/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include'
    });

    const data = await response.json();

    if (!response.ok) {
        clearAuth();
        throw new Error(data.error || 'Token refresh failed');
    }

    accessToken = data.accessToken;
    return data.accessToken;
}

/**
 * Log out — server revokes refresh token and clears cookie
 */
export async function logout() {
    try {
        await fetch(`${AUTH_API}/logout`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include'
        });
    } catch {
        // Best effort — clear local state regardless
    }

    clearAuth();
}

/**
 * Fetch with automatic token refresh on 401
 */
export async function fetchWithAuth(url, options = {}) {
    if (!accessToken) {
        throw new Error('Not authenticated');
    }

    const authOptions = {
        ...options,
        credentials: 'include',
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${accessToken}`
        }
    };

    let response = await fetch(url, authOptions);

    // If 401, try to refresh the token and retry
    if (response.status === 401) {
        try {
            const newToken = await refreshTokens();
            authOptions.headers['Authorization'] = `Bearer ${newToken}`;
            response = await fetch(url, authOptions);
        } catch {
            clearAuth();
            throw new Error('Session expired. Please log in again.');
        }
    }

    return response;
}

/**
 * Get current user from API
 */
export async function getCurrentUser() {
    const response = await fetchWithAuth(`${AUTH_API}/me`);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || 'Failed to get user');
    }

    return data.user;
}

/**
 * Verify email with token from link
 */
export async function verifyEmailToken(token) {
    const response = await fetch(`${AUTH_API}/verify-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token })
    });

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || 'Verification failed');
    }
    return data;
}

/**
 * Resend verification email
 */
export async function resendVerification() {
    const response = await fetchWithAuth(`${AUTH_API}/resend-verification`, {
        method: 'POST'
    });

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || 'Failed to resend verification');
    }
    return data;
}

/**
 * Request password reset email
 */
export async function forgotPassword(email) {
    const response = await fetch(`${AUTH_API}/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email })
    });

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || 'Failed to send reset email');
    }
    return data;
}

/**
 * Reset password with token from email
 */
export async function resetPasswordWithToken(token, password) {
    const response = await fetch(`${AUTH_API}/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token, password })
    });

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || 'Password reset failed');
    }
    return data;
}
