import React, { useState, useEffect } from 'react';
import { ArrowLeft, Check, CheckCircle, Mail, Shield, Save, Loader } from 'lucide-react';
import { ASSETS, ASSET_CATEGORIES } from '../../data/assets';
import { getUserAssets, setUserAssets } from '../../services/userService';
import { resendVerification } from '../../services/authService';
import './Settings.css';

// Group assets by category
const CATEGORY_LIST = Object.values(ASSET_CATEGORIES);
const assetsByCategory = {};
CATEGORY_LIST.forEach(cat => {
    const assets = ASSETS.filter(a => a.category === cat);
    if (assets.length > 0) assetsByCategory[cat] = assets;
});

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

    const selectAllInCategory = (category) => {
        setSelectedAssets(prev => {
            const next = new Set(prev);
            assetsByCategory[category].forEach(a => next.add(a.id));
            return next;
        });
        setSaveStatus(null);
    };

    const deselectAllInCategory = (category) => {
        setSelectedAssets(prev => {
            const next = new Set(prev);
            assetsByCategory[category].forEach(a => next.delete(a.id));
            return next;
        });
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

    const allCategorySelected = (category) =>
        assetsByCategory[category]?.every(a => selectedAssets.has(a.id));

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
                        <span className="settings-asset-count">
                            {selectedAssets.size} / {ASSETS.length} selected
                        </span>
                    </div>

                    {isLoading ? (
                        <div className="settings-loading">
                            <Loader size={24} style={{ animation: 'spin 1s linear infinite' }} />
                            <span>Loading preferences...</span>
                        </div>
                    ) : (
                        <div className="settings-categories">
                            {Object.entries(assetsByCategory).map(([category, assets]) => (
                                <div key={category} className="settings-category">
                                    <div className="settings-category-header">
                                        <span className="settings-category-name">{category}</span>
                                        <div className="settings-category-actions">
                                            {allCategorySelected(category) ? (
                                                <button
                                                    className="settings-cat-btn"
                                                    onClick={() => deselectAllInCategory(category)}
                                                >
                                                    Deselect All
                                                </button>
                                            ) : (
                                                <button
                                                    className="settings-cat-btn"
                                                    onClick={() => selectAllInCategory(category)}
                                                >
                                                    Select All
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                    <div className="settings-asset-grid">
                                        {assets.map(asset => (
                                            <label
                                                key={asset.id}
                                                className={`settings-asset-item ${selectedAssets.has(asset.id) ? 'selected' : ''}`}
                                            >
                                                <div className="settings-checkbox">
                                                    {selectedAssets.has(asset.id) && <Check size={12} />}
                                                </div>
                                                <span className="settings-asset-name">{asset.name}</span>
                                                <input
                                                    type="checkbox"
                                                    checked={selectedAssets.has(asset.id)}
                                                    onChange={() => toggleAsset(asset.id)}
                                                    className="sr-only"
                                                />
                                            </label>
                                        ))}
                                    </div>
                                </div>
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
