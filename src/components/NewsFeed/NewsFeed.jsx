import React, { useState, useEffect } from 'react';
import { Newspaper, RefreshCw, Search, Filter, ExternalLink, Clock, X, ChevronLeft, ChevronRight } from 'lucide-react';
import { fetchAllNews, NEWS_SOURCES, searchNews, getNewsBySource, clearNewsCache } from '../../services/newsFeeds';
import NewsModal from './NewsModal';
import './NewsFeed.css';

const NewsFeed = ({ isCollapsed = false, onToggleCollapse }) => {
    const [news, setNews] = useState([]);
    const [filteredNews, setFilteredNews] = useState([]);
    const [isLoading, setIsLoading] = useState(true);
    const [loadingSource, setLoadingSource] = useState('');
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedSource, setSelectedSource] = useState('all');
    const [selectedArticle, setSelectedArticle] = useState(null);
    const [showFilters, setShowFilters] = useState(false);

    // Fetch news on mount
    useEffect(() => {
        loadNews();
    }, []);

    // Filter news when search or source changes, maintain chronological order
    useEffect(() => {
        let result = [...news];

        if (selectedSource !== 'all') {
            result = getNewsBySource(result, selectedSource);
        }

        if (searchQuery) {
            result = searchNews(result, searchQuery);
        }

        // Ensure chronological order (newest first) using timestamp
        result.sort((a, b) => {
            const timestampA = a.pubDateTimestamp || new Date(a.pubDate).getTime();
            const timestampB = b.pubDateTimestamp || new Date(b.pubDate).getTime();
            return timestampB - timestampA; // Newest (higher timestamp) first
        });

        setFilteredNews(result);
    }, [news, searchQuery, selectedSource]);

    const loadNews = async (forceRefresh = false) => {
        setIsLoading(true);
        try {
            const items = await fetchAllNews(forceRefresh, (current, total, sourceName) => {
                setLoadingSource(sourceName);
            });

            // Ensure items are sorted by timestamp (newest first)
            const sortedItems = [...items].sort((a, b) => {
                const timestampA = a.pubDateTimestamp || new Date(a.pubDate).getTime();
                const timestampB = b.pubDateTimestamp || new Date(b.pubDate).getTime();
                return timestampB - timestampA; // Newest (higher timestamp) first
            });

            setNews(sortedItems);
            setFilteredNews(sortedItems);
        } catch (error) {
            console.error('Failed to load news:', error);
        } finally {
            setIsLoading(false);
            setLoadingSource('');
        }
    };

    const handleRefresh = () => {
        clearNewsCache();
        loadNews(true);
    };

    const formatTimeAgo = (date) => {
        // Ensure we have a valid Date object
        const dateObj = date instanceof Date ? date : new Date(date);
        if (isNaN(dateObj.getTime())) return 'Unknown';

        const now = new Date();
        const diff = now.getTime() - dateObj.getTime();
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);

        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes} min ago`;
        if (hours < 24) return `${hours} hr ago`;
        if (days < 7) return `${days}d ago`;
        return dateObj.toLocaleDateString();
    };

    // Collapsed view - just show toggle button
    if (isCollapsed) {
        return (
            <div className="news-feed collapsed">
                <button
                    className="news-feed-expand-btn"
                    onClick={onToggleCollapse}
                    title="Expand News Feed"
                >
                    <ChevronLeft size={18} />
                    <Newspaper size={20} />
                    <span className="news-feed-expand-label">News</span>
                    {filteredNews.length > 0 && (
                        <span className="news-badge">{filteredNews.length}</span>
                    )}
                </button>
            </div>
        );
    }

    return (
        <div className="news-feed">
            {/* Header */}
            <div className="news-feed-header">
                <button
                    className="news-collapse-btn"
                    onClick={onToggleCollapse}
                    title="Collapse News Feed"
                >
                    <ChevronRight size={18} />
                </button>
                <div className="news-feed-title">
                    <Newspaper size={20} />
                    <h2>Security News Feed</h2>
                    <span className="news-count">{filteredNews.length} articles</span>
                </div>
                <div className="news-feed-actions">
                    <button
                        className="news-action-btn"
                        onClick={() => setShowFilters(!showFilters)}
                        title="Filter sources"
                    >
                        <Filter size={16} />
                    </button>
                    <button
                        className="news-action-btn"
                        onClick={handleRefresh}
                        disabled={isLoading}
                        title="Refresh feeds"
                    >
                        <RefreshCw size={16} className={isLoading ? 'spinning' : ''} />
                    </button>
                </div>
            </div>

            {/* Search Bar */}
            <div className="news-search">
                <Search size={16} />
                <input
                    type="text"
                    placeholder="Search news..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                />
                {searchQuery && (
                    <button className="search-clear" onClick={() => setSearchQuery('')}>
                        <X size={14} />
                    </button>
                )}
            </div>

            {/* Source Filters */}
            {showFilters && (
                <div className="news-filters">
                    <button
                        className={`source-filter ${selectedSource === 'all' ? 'active' : ''}`}
                        onClick={() => setSelectedSource('all')}
                    >
                        All Sources
                    </button>
                    {NEWS_SOURCES.map(source => (
                        <button
                            key={source.id}
                            className={`source-filter ${selectedSource === source.id ? 'active' : ''}`}
                            onClick={() => setSelectedSource(source.id)}
                            style={{ '--source-color': source.color }}
                        >
                            {source.name}
                        </button>
                    ))}
                </div>
            )}

            {/* Loading State */}
            {isLoading && (
                <div className="news-loading">
                    <RefreshCw className="spinning" size={24} />
                    <span>Loading {loadingSource || 'news feeds'}...</span>
                </div>
            )}

            {/* News List */}
            <div className="news-list">
                {!isLoading && filteredNews.length === 0 && (
                    <div className="news-empty">
                        <Newspaper size={32} />
                        <p>No news articles found</p>
                    </div>
                )}

                {filteredNews.map(article => (
                    <article
                        key={article.id}
                        className="news-item"
                        onClick={() => setSelectedArticle(article)}
                    >
                        {article.thumbnail && (
                            <div className="news-item-image">
                                <img
                                    src={article.thumbnail}
                                    alt=""
                                    onError={(e) => e.target.style.display = 'none'}
                                />
                            </div>
                        )}
                        <div className="news-item-content">
                            <div className="news-item-source">
                                <span
                                    className="source-badge"
                                    style={{ backgroundColor: article.source.color }}
                                >
                                    {article.source.name}
                                </span>
                                <span className="news-item-time">
                                    <Clock size={12} />
                                    {formatTimeAgo(article.pubDate)}
                                </span>
                            </div>
                            <h3 className="news-item-title">{article.title}</h3>
                            <p className="news-item-description">{article.description}</p>
                            <div className="news-item-footer">
                                <span className="news-item-author">{article.author}</span>
                                <ExternalLink size={12} />
                            </div>
                        </div>
                    </article>
                ))}
            </div>

            {/* Article Modal */}
            {selectedArticle && (
                <NewsModal
                    article={selectedArticle}
                    onClose={() => setSelectedArticle(null)}
                />
            )}
        </div>
    );
};

export default NewsFeed;
