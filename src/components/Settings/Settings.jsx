import React, { useState, useEffect } from 'react';
import { ArrowLeft, CheckCircle, Mail, Shield, Save, Loader } from 'lucide-react';
import { ASSETS } from '../../data/assets';
import { getUserAssets, setUserAssets } from '../../services/userService';
import { resendVerification } from '../../services/authService';
import './Settings.css';

// Sorted alphabetically once
const SORTED_ASSETS = [...ASSETS].sort((a, b) => a.name.localeCompare(b.name));

const Settings = ({ user, onBack, onAssetsChanged, onEmailVerified }) => {
    const [selectedAssets, setSelectedAssets] = useState(new Set(ASSETS.map(a => a.id)));
    const [initialAssets, setInitialAssets] = useState(null);
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [saveStatus, setSaveStatus] = useState(null); // null | 'saved' | 'error'
    const [verificationSent, setVerificationSent] = useState(false);
    const [verificationSending, setVerificationSending] = useState(false);

    // Load user's asset preferences
    useEffect(() => {
        getUserAssets()
            .then(assets => {
                if (assets) {
                    setSelectedAssets(new Set(assets));
                    setInitialAssets(new Set(assets));
                } else {
                    // null = no preferences, all selected
                    const all = new Set(ASSETS.map(a => a.id));
                    setSelectedAssets(all);
                    setInitialAssets(null);
                }
            })
            .catch(err => console.error('Failed to load asset preferences:', err))
            .finally(() => setIsLoading(false));
    }, []);

    const toggleAsset = (assetId) => {
        setSelectedAssets(prev => {
            const next = new Set(prev);
            if (next.has(assetId)) {
                next.delete(assetId);
            } else {
                next.add(assetId);
            }
            return next;
        });
        setSaveStatus(null);
    };

    const selectAll = () => {
        setSelectedAssets(new Set(ASSETS.map(a => a.id)));
        setSaveStatus(null);
    };

    const deselectAll = () => {
        setSelectedAssets(new Set());
        setSaveStatus(null);
    };

    const handleSave = async () => {
        setIsSaving(true);
        setSaveStatus(null);
        try {
            const ids = Array.from(selectedAssets);
            await setUserAssets(ids);
            setInitialAssets(new Set(ids));
            setSaveStatus('saved');
            if (onAssetsChanged) onAssetsChanged(ids);
        } catch (err) {
            console.error('Failed to save:', err);
            setSaveStatus('error');
        } finally {
            setIsSaving(false);
        }
    };

    const handleResendVerification = async () => {
        setVerificationSending(true);
        try {
            await resendVerification();
            setVerificationSent(true);
        } catch (err) {
            console.error('Failed to resend verification:', err);
        } finally {
            setVerificationSending(false);
        }
    };

    const hasChanges = (() => {
        if (initialAssets === null) {
            // No preferences saved yet — changed if not all selected
            return selectedAssets.size !== ASSETS.length;
        }
        if (selectedAssets.size !== initialAssets.size) return true;
        for (const id of selectedAssets) {
            if (!initialAssets.has(id)) return true;
        }
        return false;
    })();

    const allSelected = selectedAssets.size === ASSETS.length;

    return (
        <div className="settings-page">
            <div className="settings-header">
                <button className="settings-back-btn" onClick={onBack}>
                    <ArrowLeft size={18} />
                    <span>Dashboard</span>
                </button>
                <h1 className="settings-title">Settings</h1>
            </div>

            <div className="settings-content">
                {/* Account Section */}
                <section className="settings-section">
                    <h2 className="settings-section-title">Account</h2>
                    <div className="settings-card">
                        <div className="settings-row">
                            <div className="settings-row-label">
                                <Mail size={16} />
                                Email
                            </div>
                            <div className="settings-row-value">{user?.email}</div>
                        </div>

                        <div className="settings-row">
                            <div className="settings-row-label">
                                <Shield size={16} />
                                Verification
                            </div>
                            <div className="settings-row-value">
                                {user?.emailVerified ? (
                                    <span className="settings-verified">
                                        <CheckCircle size={14} />
                                        Verified
                                    </span>
                                ) : (
                                    <div className="settings-unverified">
                                        <span>Not verified</span>
                                        {verificationSent ? (
                                            <span className="settings-verification-sent">Email sent!</span>
                                        ) : (
                                            <button
                                                className="settings-resend-btn"
                                                onClick={handleResendVerification}
                                                disabled={verificationSending}
                                            >
                                                {verificationSending ? 'Sending...' : 'Resend Verification'}
                                            </button>
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>

                        {user?.createdAt && (
                            <div className="settings-row">
                                <div className="settings-row-label">Member since</div>
                                <div className="settings-row-value">
                                    {new Date(user.createdAt).toLocaleDateString()}
                                </div>
                            </div>
                        )}
                    </div>
                </section>

                {/* Monitored Assets Section */}
                <section className="settings-section">
                    <div className="settings-section-header">
                        <h2 className="settings-section-title">Monitored Assets</h2>
                        <div className="settings-section-actions">
                            <span className="settings-asset-count">
                                {selectedAssets.size} / {ASSETS.length}
                            </span>
                            <button
                                className="settings-toggle-all-btn"
                                onClick={allSelected ? deselectAll : selectAll}
                            >
                                {allSelected ? 'Deselect All' : 'Select All'}
                            </button>
                        </div>
                    </div>

                    {isLoading ? (
                        <div className="settings-loading">
                            <Loader size={24} style={{ animation: 'spin 1s linear infinite' }} />
                            <span>Loading preferences...</span>
                        </div>
                    ) : (
                        <div className="settings-asset-columns">
                            {SORTED_ASSETS.map(asset => (
                                <label
                                    key={asset.id}
                                    className={`settings-asset-row ${selectedAssets.has(asset.id) ? 'selected' : ''}`}
                                >
                                    <input
                                        type="checkbox"
                                        checked={selectedAssets.has(asset.id)}
                                        onChange={() => toggleAsset(asset.id)}
                                        className="settings-native-checkbox"
                                    />
                                    <span className="settings-asset-name">{asset.name}</span>
                                </label>
                            ))}
                        </div>
                    )}

                    <div className="settings-save-bar">
                        <button
                            className="settings-save-btn"
                            onClick={handleSave}
                            disabled={isSaving || !hasChanges}
                        >
                            {isSaving ? (
                                <Loader size={16} style={{ animation: 'spin 1s linear infinite' }} />
                            ) : (
                                <Save size={16} />
                            )}
                            {isSaving ? 'Saving...' : 'Save Preferences'}
                        </button>
                        {saveStatus === 'saved' && (
                            <span className="settings-save-status success">
                                <CheckCircle size={14} /> Saved!
                            </span>
                        )}
                        {saveStatus === 'error' && (
                            <span className="settings-save-status error">
                                Failed to save. Try again.
                            </span>
                        )}
                    </div>
                </section>
            </div>
        </div>
    );
};

export default Settings;
