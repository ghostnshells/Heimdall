import React, { useState } from 'react';
import { Mail, ArrowLeft, CheckCircle, AlertCircle } from 'lucide-react';
import { forgotPassword } from '../../services/authService';
import './ForgotPassword.css';

const ForgotPassword = ({ onBack }) => {
    const [email, setEmail] = useState('');
    const [status, setStatus] = useState('idle'); // idle | loading | sent | error
    const [error, setError] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setStatus('loading');
        setError(null);

        try {
            await forgotPassword(email);
            setStatus('sent');
        } catch (err) {
            setError(err.message);
            setStatus('error');
        }
    };

    return (
        <div className="login-page">
            <div className="login-card">
                <button className="forgot-back-btn" onClick={onBack}>
                    <ArrowLeft size={16} />
                    Back to Sign In
                </button>

                {status === 'sent' ? (
                    <div className="forgot-success">
                        <CheckCircle size={48} style={{ color: 'var(--status-success)' }} />
                        <h2>Check your email</h2>
                        <p>
                            If an account exists for <strong>{email}</strong>, we've sent a password reset link.
                            It expires in 1 hour.
                        </p>
                        <button className="login-submit" onClick={onBack}>
                            Back to Sign In
                        </button>
                    </div>
                ) : (
                    <>
                        <div className="login-header">
                            <h1 className="login-title" style={{ letterSpacing: 0 }}>Forgot Password</h1>
                            <p className="login-subtitle">Enter your email and we'll send you a reset link.</p>
                        </div>

                        <form className="login-form" onSubmit={handleSubmit}>
                            {error && (
                                <div className="login-error">
                                    <AlertCircle size={14} />
                                    {error}
                                </div>
                            )}

                            <div className="login-field">
                                <label className="login-label" htmlFor="reset-email">
                                    <Mail size={14} />
                                    Email
                                </label>
                                <input
                                    id="reset-email"
                                    type="email"
                                    className="login-input"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    placeholder="you@example.com"
                                    required
                                    autoComplete="email"
                                />
                            </div>

                            <button
                                type="submit"
                                className="login-submit"
                                disabled={status === 'loading'}
                            >
                                {status === 'loading' ? (
                                    <span className="login-spinner" />
                                ) : (
                                    'Send Reset Link'
                                )}
                            </button>
                        </form>
                    </>
                )}
            </div>
        </div>
    );
};

export default ForgotPassword;
