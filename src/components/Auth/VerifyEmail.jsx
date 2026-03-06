import React, { useEffect, useState } from 'react';
import { CheckCircle, XCircle, Loader } from 'lucide-react';
import { verifyEmailToken } from '../../services/authService';

const VerifyEmail = ({ token, onComplete }) => {
    const [status, setStatus] = useState('verifying'); // verifying | success | error
    const [error, setError] = useState(null);

    useEffect(() => {
        if (!token) {
            setStatus('error');
            setError('No verification token provided');
            return;
        }

        verifyEmailToken(token)
            .then(() => setStatus('success'))
            .catch(err => {
                setStatus('error');
                setError(err.message);
            });
    }, [token]);

    return (
        <div className="login-page">
            <div className="login-card" style={{ textAlign: 'center' }}>
                {status === 'verifying' && (
                    <>
                        <Loader size={40} style={{ color: 'var(--accent-primary)', animation: 'spin 1s linear infinite', marginBottom: 16 }} />
                        <h2 style={{ color: 'var(--text-primary)', marginBottom: 8 }}>Verifying your email...</h2>
                        <p style={{ color: 'var(--text-tertiary)', fontSize: 14 }}>Please wait a moment.</p>
                    </>
                )}

                {status === 'success' && (
                    <>
                        <CheckCircle size={48} style={{ color: 'var(--status-success)', marginBottom: 16 }} />
                        <h2 style={{ color: 'var(--text-primary)', marginBottom: 8 }}>Email Verified!</h2>
                        <p style={{ color: 'var(--text-tertiary)', fontSize: 14, marginBottom: 24 }}>
                            Your email has been successfully verified.
                        </p>
                        <button className="login-submit" onClick={onComplete}>
                            Continue to Dashboard
                        </button>
                    </>
                )}

                {status === 'error' && (
                    <>
                        <XCircle size={48} style={{ color: 'var(--severity-critical)', marginBottom: 16 }} />
                        <h2 style={{ color: 'var(--text-primary)', marginBottom: 8 }}>Verification Failed</h2>
                        <p style={{ color: 'var(--text-tertiary)', fontSize: 14, marginBottom: 24 }}>
                            {error || 'The verification link is invalid or has expired.'}
                        </p>
                        <button className="login-submit" onClick={onComplete}>
                            Go to Dashboard
                        </button>
                    </>
                )}
            </div>
        </div>
    );
};

export default VerifyEmail;
