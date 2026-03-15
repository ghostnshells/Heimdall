import React, { useState, useEffect } from 'react';
import { Shield, Mail, Lock, LogIn, UserPlus, AlertCircle } from 'lucide-react';
import { getOAuthProviders, startOAuthFlow } from '../../services/authService';
import './LoginPage.css';

// SVG icons for OAuth providers (inline to avoid dependencies)
const GoogleIcon = () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18A10.96 10.96 0 001 12c0 1.77.42 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
    </svg>
);

const MicrosoftIcon = () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
        <rect x="1" y="1" width="10" height="10" fill="#F25022"/>
        <rect x="13" y="1" width="10" height="10" fill="#7FBA00"/>
        <rect x="1" y="13" width="10" height="10" fill="#00A4EF"/>
        <rect x="13" y="13" width="10" height="10" fill="#FFB900"/>
    </svg>
);

const GitHubIcon = () => (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
    </svg>
);

const providerConfig = {
    google: { icon: GoogleIcon, label: 'Google', className: 'oauth-google' },
    microsoft: { icon: MicrosoftIcon, label: 'Microsoft', className: 'oauth-microsoft' },
    github: { icon: GitHubIcon, label: 'GitHub', className: 'oauth-github' },
};

const LoginPage = ({ onLogin, onForgotPassword, onOAuthLogin }) => {
    const [isSignup, setIsSignup] = useState(false);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState(null);
    const [isLoading, setIsLoading] = useState(false);
    const [oauthLoading, setOauthLoading] = useState(null);
    const [availableProviders, setAvailableProviders] = useState([]);

    // Fetch available OAuth providers on mount
    useEffect(() => {
        getOAuthProviders().then(setAvailableProviders);
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);

        if (isSignup && password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }

        if (password.length < 8) {
            setError('Password must be at least 8 characters');
            return;
        }

        setIsLoading(true);

        try {
            await onLogin(email, password, isSignup);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    const handleOAuth = (provider) => {
        setError(null);
        setOauthLoading(provider);
        startOAuthFlow(provider);
        // Page navigates away — no cleanup needed
    };

    const hasOAuth = availableProviders.length > 0;

    return (
        <div className="login-page">
            <div className="login-card">
                <div className="login-header">
                    <div className="login-logo">
                        <Shield size={32} />
                    </div>
                    <h1 className="login-title">PANOPTES</h1>
                    <p className="login-subtitle">Vulnerability Monitoring Dashboard</p>
                </div>

                <form className="login-form" onSubmit={handleSubmit}>
                    <div className="login-tabs">
                        <button
                            type="button"
                            className={`login-tab ${!isSignup ? 'active' : ''}`}
                            onClick={() => { setIsSignup(false); setError(null); }}
                        >
                            <LogIn size={14} />
                            Sign In
                        </button>
                        <button
                            type="button"
                            className={`login-tab ${isSignup ? 'active' : ''}`}
                            onClick={() => { setIsSignup(true); setError(null); }}
                        >
                            <UserPlus size={14} />
                            Sign Up
                        </button>
                    </div>

                    {error && (
                        <div className="login-error">
                            <AlertCircle size={14} />
                            {error}
                        </div>
                    )}

                    {/* OAuth Buttons */}
                    {hasOAuth && (
                        <>
                            <div className="login-oauth-buttons">
                                {availableProviders.map(provider => {
                                    const config = providerConfig[provider];
                                    if (!config) return null;
                                    const Icon = config.icon;
                                    return (
                                        <button
                                            key={provider}
                                            type="button"
                                            className={`login-oauth-btn ${config.className}`}
                                            onClick={() => handleOAuth(provider)}
                                            disabled={oauthLoading !== null || isLoading}
                                        >
                                            {oauthLoading === provider ? (
                                                <span className="login-spinner" />
                                            ) : (
                                                <Icon />
                                            )}
                                            <span>Continue with {config.label}</span>
                                        </button>
                                    );
                                })}
                            </div>

                            <div className="login-divider">
                                <span>or</span>
                            </div>
                        </>
                    )}

                    <div className="login-field">
                        <label className="login-label" htmlFor="email">
                            <Mail size={14} />
                            Email
                        </label>
                        <input
                            id="email"
                            type="email"
                            className="login-input"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="you@example.com"
                            required
                            autoComplete="email"
                        />
                    </div>

                    <div className="login-field">
                        <label className="login-label" htmlFor="password">
                            <Lock size={14} />
                            Password
                        </label>
                        <input
                            id="password"
                            type="password"
                            className="login-input"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Min. 8 characters"
                            required
                            minLength={8}
                            autoComplete={isSignup ? 'new-password' : 'current-password'}
                        />
                    </div>

                    {!isSignup && onForgotPassword && (
                        <button
                            type="button"
                            className="login-forgot-link"
                            onClick={onForgotPassword}
                        >
                            Forgot Password?
                        </button>
                    )}

                    {isSignup && (
                        <div className="login-field">
                            <label className="login-label" htmlFor="confirmPassword">
                                <Lock size={14} />
                                Confirm Password
                            </label>
                            <input
                                id="confirmPassword"
                                type="password"
                                className="login-input"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                placeholder="Re-enter password"
                                required
                                minLength={8}
                                autoComplete="new-password"
                            />
                        </div>
                    )}

                    <button
                        type="submit"
                        className="login-submit"
                        disabled={isLoading || oauthLoading !== null}
                    >
                        {isLoading ? (
                            <span className="login-spinner" />
                        ) : (
                            <>
                                {isSignup ? <UserPlus size={16} /> : <LogIn size={16} />}
                                {isSignup ? 'Create Account' : 'Sign In'}
                            </>
                        )}
                    </button>
                </form>
            </div>
        </div>
    );
};

export default LoginPage;
