import React, { useEffect } from 'react';
import { X, ExternalLink, Clock, User, Share2, BookmarkPlus } from 'lucide-react';

const NewsModal = ({ article, onClose }) => {
    // Close on escape key
    useEffect(() => {
        const handleEscape = (e) => {
            if (e.key === 'Escape') {
                onClose();
            }
        };
        document.addEventListener('keydown', handleEscape);
        document.body.style.overflow = 'hidden';

        return () => {
            document.removeEventListener('keydown', handleEscape);
            document.body.style.overflow = 'auto';
        };
    }, [onClose]);

    const formatDate = (date) => {
        return date.toLocaleDateString('en-US', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    const handleOverlayClick = (e) => {
        if (e.target === e.currentTarget) {
            onClose();
        }
    };

    const handleReadMore = () => {
        window.open(article.link, '_blank', 'noopener,noreferrer');
    };

    const handleShare = async () => {
        if (navigator.share) {
            try {
                await navigator.share({
                    title: article.title,
                    text: article.description,
                    url: article.link
                });
            } catch (err) {
                console.log('Share cancelled');
            }
        } else {
            // Fallback: copy to clipboard
            navigator.clipboard.writeText(article.link);
            alert('Link copied to clipboard!');
        }
    };

    return (
        <div className="news-modal-overlay" onClick={handleOverlayClick}>
            <div className="news-modal">
                {/* Modal Header */}
                <div className="news-modal-header">
                    <div className="news-modal-source">
                        <span
                            className="source-badge large"
                            style={{ backgroundColor: article.source.color }}
                        >
                            {article.source.name}
                        </span>
                    </div>
                    <div className="news-modal-actions">
                        <button
                            className="modal-action-btn"
                            onClick={handleShare}
                            title="Share article"
                        >
                            <Share2 size={18} />
                        </button>
                        <button
                            className="modal-action-btn"
                            onClick={onClose}
                            title="Close"
                        >
                            <X size={20} />
                        </button>
                    </div>
                </div>

                {/* Article Image */}
                {article.thumbnail && (
                    <div className="news-modal-image">
                        <img
                            src={article.thumbnail}
                            alt={article.title}
                            onError={(e) => e.target.parentElement.style.display = 'none'}
                        />
                    </div>
                )}

                {/* Article Content */}
                <div className="news-modal-content">
                    <h1 className="news-modal-title">{article.title}</h1>

                    <div className="news-modal-meta">
                        <span className="meta-item">
                            <User size={14} />
                            {article.author}
                        </span>
                        <span className="meta-item">
                            <Clock size={14} />
                            {formatDate(article.pubDate)}
                        </span>
                    </div>

                    <div
                        className="news-modal-body"
                        dangerouslySetInnerHTML={{ __html: sanitizeHtml(article.content) }}
                    />

                    {/* Read More Button */}
                    <div className="news-modal-footer">
                        <button
                            className="read-more-btn"
                            onClick={handleReadMore}
                        >
                            <span>Read Full Article</span>
                            <ExternalLink size={16} />
                        </button>
                        <p className="source-attribution">
                            Source: <a href={article.link} target="_blank" rel="noopener noreferrer">
                                {article.source.name}
                            </a>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

/**
 * Basic HTML sanitization to prevent XSS
 * Allows only safe tags for article content display
 */
const sanitizeHtml = (html) => {
    if (!html) return '';

    // Create a temporary element
    const temp = document.createElement('div');
    temp.innerHTML = html;

    // Remove script tags
    const scripts = temp.querySelectorAll('script');
    scripts.forEach(s => s.remove());

    // Remove event handlers
    const allElements = temp.querySelectorAll('*');
    allElements.forEach(el => {
        // Remove event handlers
        Array.from(el.attributes).forEach(attr => {
            if (attr.name.startsWith('on')) {
                el.removeAttribute(attr.name);
            }
        });
        // Remove javascript: urls
        if (el.href && el.href.startsWith('javascript:')) {
            el.removeAttribute('href');
        }
    });

    return temp.innerHTML;
};

export default NewsModal;
