// OAuth2 provider configurations for Google, Microsoft, and GitHub
// Each provider implements the Authorization Code flow

const providers = {
    google: {
        authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenUrl: 'https://oauth2.googleapis.com/token',
        userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
        scopes: ['openid', 'email', 'profile'],
        getClientId: () => process.env.GOOGLE_CLIENT_ID,
        getClientSecret: () => process.env.GOOGLE_CLIENT_SECRET,
        extractUser: (data) => ({
            providerId: data.id,
            email: data.email,
            displayName: data.name || data.email,
            avatarUrl: data.picture || null,
        }),
    },
    microsoft: {
        authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
        scopes: ['openid', 'email', 'profile', 'User.Read'],
        getClientId: () => process.env.MICROSOFT_CLIENT_ID,
        getClientSecret: () => process.env.MICROSOFT_CLIENT_SECRET,
        extractUser: (data) => ({
            providerId: data.id,
            email: data.mail || data.userPrincipalName,
            displayName: data.displayName || data.userPrincipalName,
            avatarUrl: null, // Microsoft Graph requires separate photo endpoint
        }),
    },
    github: {
        authUrl: 'https://github.com/login/oauth/authorize',
        tokenUrl: 'https://github.com/login/oauth/access_token',
        userInfoUrl: 'https://api.github.com/user',
        emailUrl: 'https://api.github.com/user/emails',
        scopes: ['read:user', 'user:email'],
        getClientId: () => process.env.GITHUB_CLIENT_ID,
        getClientSecret: () => process.env.GITHUB_CLIENT_SECRET,
        extractUser: (data, emails) => {
            // GitHub may not return email in profile — use primary verified email from emails endpoint
            const primaryEmail = emails
                ? emails.find(e => e.primary && e.verified)?.email || emails.find(e => e.verified)?.email
                : data.email;
            return {
                providerId: String(data.id),
                email: primaryEmail,
                displayName: data.name || data.login,
                avatarUrl: data.avatar_url || null,
            };
        },
    },
};

/**
 * Build the authorization URL for a provider
 */
export function getAuthorizationUrl(providerName, redirectUri, state) {
    const provider = providers[providerName];
    if (!provider) throw new Error(`Unknown OAuth provider: ${providerName}`);

    const clientId = provider.getClientId();
    if (!clientId) throw new Error(`OAuth not configured for ${providerName}`);

    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: provider.scopes.join(' '),
        state,
    });

    // Provider-specific params
    if (providerName === 'google') {
        params.set('access_type', 'offline');
        params.set('prompt', 'select_account');
    }
    if (providerName === 'microsoft') {
        params.set('response_mode', 'query');
    }

    return `${provider.authUrl}?${params.toString()}`;
}

/**
 * Exchange authorization code for tokens and fetch user profile
 */
export async function exchangeCodeForUser(providerName, code, redirectUri) {
    const provider = providers[providerName];
    if (!provider) throw new Error(`Unknown OAuth provider: ${providerName}`);

    const clientId = provider.getClientId();
    const clientSecret = provider.getClientSecret();
    if (!clientId || !clientSecret) throw new Error(`OAuth not configured for ${providerName}`);

    // Exchange code for access token
    const tokenBody = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
    });

    const tokenRes = await fetch(provider.tokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
        },
        body: tokenBody.toString(),
    });

    const tokenData = await tokenRes.json();

    if (tokenData.error) {
        throw new Error(`OAuth token exchange failed: ${tokenData.error_description || tokenData.error}`);
    }

    const accessToken = tokenData.access_token;
    if (!accessToken) {
        throw new Error('No access token received from OAuth provider');
    }

    // Fetch user profile
    const userRes = await fetch(provider.userInfoUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!userRes.ok) {
        throw new Error(`Failed to fetch user profile from ${providerName}`);
    }

    const userData = await userRes.json();

    // GitHub: fetch emails separately if needed
    let emails = null;
    if (providerName === 'github' && provider.emailUrl) {
        const emailRes = await fetch(provider.emailUrl, {
            headers: { Authorization: `Bearer ${accessToken}` },
        });
        if (emailRes.ok) {
            emails = await emailRes.json();
        }
    }

    const userInfo = provider.extractUser(userData, emails);

    if (!userInfo.email) {
        throw new Error(`Could not get email from ${providerName}. Please ensure your email is public or verified.`);
    }

    return userInfo;
}

/**
 * Get list of available (configured) providers
 */
export function getAvailableProviders() {
    return Object.keys(providers).filter(name => {
        const p = providers[name];
        return p.getClientId() && p.getClientSecret();
    });
}
