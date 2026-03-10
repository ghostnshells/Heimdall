// Shared cookie helpers for serverless auth handlers

const COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    path: '/api/auth',
    maxAge: 7 * 24 * 60 * 60 // seconds
};

export function parseCookies(req) {
    if (req.cookies) return req.cookies;
    const header = req.headers?.cookie || '';
    const cookies = {};
    for (const pair of header.split(';')) {
        const [name, ...rest] = pair.trim().split('=');
        if (name) cookies[name] = decodeURIComponent(rest.join('='));
    }
    return cookies;
}

export function serializeRefreshTokenCookie(token) {
    const parts = [
        `refreshToken=${encodeURIComponent(token)}`,
        `HttpOnly`,
        `Path=${COOKIE_OPTIONS.path}`,
        `SameSite=${COOKIE_OPTIONS.sameSite}`,
        `Max-Age=${COOKIE_OPTIONS.maxAge}`
    ];
    if (COOKIE_OPTIONS.secure) parts.push('Secure');
    return parts.join('; ');
}

export function clearRefreshTokenCookie() {
    const parts = [
        `refreshToken=`,
        `HttpOnly`,
        `Path=${COOKIE_OPTIONS.path}`,
        `SameSite=${COOKIE_OPTIONS.sameSite}`,
        `Max-Age=0`
    ];
    if (COOKIE_OPTIONS.secure) parts.push('Secure');
    return parts.join('; ');
}
