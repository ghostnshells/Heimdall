import React, { useState } from 'react';
import { Lock, CheckCircle, AlertCircle } from 'lucide-react';
import { resetPasswordWithToken } from '../../services/authService';
import './ResetPassword.css';

const ResetPassword = ({ token, onComplete }) => {
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [status, setStatus] = useState('idle'); // idle | loading | success | error
    const [error, setError] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);

        if (password !== confirmPassword) {
            setError('Passwords do not match');
            return;
        }
        if (password.length < 8) {
            setError('Password must be at least 8 characters');
            return;
        }

        setStatus('loading');

        try {
            await resetPasswordWithToken(token, password);
            setStatus('success');
        } catch (err) {
            setError(err.message);
            setStatus('error');
        }
    };

    if (status === 'success') {
        return (
            <div className="login-page">
                <div className="login-card" style={{ textAlign: 'center' }}>
                    <CheckCircle size={48} style={{ color: 'var(--status-success)', marginBottom: 16 }} />
                    <h2 style={{ color: 'var(--text-primary)', marginBottom: 8 }}>Password Reset!</h2>
                    <p style={{ color: 'var(--text-tertiary)', fontSize: 14, marginBottom: 24 }}>
                        Your password has been changed. You can now sign in with your new password.
                    </p>
                    <button className="login-submit" onClick={onComplete}>
                        Sign In
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="login-page">
            <div className="login-card">
                <div className="login-header">
                    <h1 className="login-title" style={{ letterSpacing: 0 }}>Reset Password</h1>
                    <p className="login-subtitle">Choose a new password for your account.</p>
                </div>

                <form className="login-form" onSubmit={handleSubmit}>
                    {error && (
                        <div className="login-error">
                            <AlertCircle size={14} />
                            {error}
                        </div>
                    )}

                    <div className="login-field">
                        <label className="login-label" htmlFor="new-password">
                            <Lock size={14} />
                            New Password
                        </label>
                        <input
                            id="new-password"
                            type="password"
                            className="login-input"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Min. 8 characters"
                            required
                            minLength={8}
                            autoComplete="new-password"
                        />
                    </div>

                    <div className="login-field">
                        <label className="login-label" htmlFor="confirm-new-password">
                            <Lock size={14} />
                            Confirm Password
                        </label>
                        <input
                            id="confirm-new-password"
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

                    <button
                        type="submit"
                        className="login-submit"
                        disabled={status === 'loading'}
                    >
                        {status === 'loading' ? (
                            <span className="login-spinner" />
                        ) : (
                            'Reset Password'
                        )}
                    </button>
                </form>
            </div>
        </div>
    );
};

export default ResetPassword;
