/**
 * Mozilla Security Advisories Service
 * Fetches security advisories directly from Mozilla
 * Feed URL: https://www.mozilla.org/en-US/security/advisories/cve-feed.json
 *
 * Benefits over NVD:
 * - Same-day updates from Mozilla
 * - Includes Firefox-specific impact information
 * - Direct from the source
 */

const MOZILLA_CVE_FEED = 'https://www.mozilla.org/en-US/security/advisories/cve-feed.json';
const MOZILLA_ADVISORIES_BASE = 'https://www.mozilla.org/en-US/security/advisories/';

// Cache for Mozilla data
let mozillaCache = {
    data: null,
    fetchedAt: null,
    cacheMs: 60 * 60 * 1000 // 1 hour cache
};

/**
 * Fetch and parse Mozilla CVE feed
 */
const fetchMozillaFeed = async () => {
    try {
        const response = await fetch(MOZILLA_CVE_FEED, {
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Mozilla API error: ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('[Mozilla API] Error fetching CVE feed:', error.message);
        return null;
    }
};

/**
 * Parse Mozilla CVE feed into normalized vulnerability format
 */
const parseMozillaFeed = (data) => {
    const vulnerabilities = [];

    if (!data || !Array.isArray(data)) {
        return vulnerabilities;
    }

    data.forEach(cve => {
        // Skip if no CVE ID
        if (!cve.cve_id || !cve.cve_id.startsWith('CVE-')) {
            return;
        }

        // Get severity from impact rating
        let severity = 'UNKNOWN';
        let cvssScore = null;

        if (cve.impact) {
            const impactMap = {
                'critical': 'CRITICAL',
                'high': 'HIGH',
                'moderate': 'MEDIUM',
                'medium': 'MEDIUM',
                'low': 'LOW',
                'none': 'NONE'
            };
            severity = impactMap[cve.impact.toLowerCase()] || 'UNKNOWN';

            // Estimate CVSS from severity for sorting
            const cvssEstimate = {
                'CRITICAL': 9.5,
                'HIGH': 7.5,
                'MEDIUM': 5.5,
                'LOW': 2.5,
                'NONE': 0
            };
            cvssScore = cvssEstimate[severity] || null;
        }

        // Get affected products
        const affectedProducts = [];
        if (cve.products) {
            cve.products.forEach(product => {
                affectedProducts.push({
                    product: product,
                    vendor: 'Mozilla',
                    cpe: `cpe:2.3:a:mozilla:${product.toLowerCase().replace(/\s+/g, '_')}:*:*:*:*:*:*:*:*`
                });
            });
        }

        // Build references
        const references = [];

        // Add advisory URL
        if (cve.mfsa_id) {
            references.push({
                url: `${MOZILLA_ADVISORIES_BASE}${cve.mfsa_id}/`,
                source: 'Mozilla Foundation',
                tags: ['Vendor Advisory']
            });
        }

        // Add bug URLs if available
        if (cve.bugs) {
            cve.bugs.forEach(bug => {
                if (bug.url) {
                    references.push({
                        url: bug.url,
                        source: 'Mozilla Bugzilla',
                        tags: ['Issue Tracking']
                    });
                }
            });
        }

        // Add NVD reference
        references.push({
            url: `https://nvd.nist.gov/vuln/detail/${cve.cve_id}`,
            source: 'NVD',
            tags: ['Reference']
        });

        vulnerabilities.push({
            id: cve.cve_id,
            source: 'Mozilla',
            published: cve.public_date || cve.published,
            lastModified: cve.public_date || cve.published,
            description: cve.description || cve.title || 'No description available',
            cvssScore,
            severity,
            affectedProducts,
            references,
            mozillaData: {
                mfsaId: cve.mfsa_id,
                impact: cve.impact,
                title: cve.title,
                products: cve.products
            }
        });
    });

    return vulnerabilities;
};

/**
 * Fetch Mozilla/Firefox vulnerabilities for a date range
 * @param {Date} startDate
 * @param {Date} endDate
 */
export const fetchMozillaVulnerabilities = async (startDate, endDate) => {
    // Check cache
    if (mozillaCache.data && mozillaCache.fetchedAt &&
        (Date.now() - mozillaCache.fetchedAt) < mozillaCache.cacheMs) {
        console.log('[Mozilla API] Using cached data');
        return filterByDateRange(mozillaCache.data, startDate, endDate);
    }

    console.log('[Mozilla API] Fetching Mozilla security advisories...');

    const feedData = await fetchMozillaFeed();

    if (!feedData) {
        return [];
    }

    const allVulns = parseMozillaFeed(feedData);

    // Update cache
    mozillaCache.data = allVulns;
    mozillaCache.fetchedAt = Date.now();

    console.log(`[Mozilla API] Fetched ${allVulns.length} Mozilla vulnerabilities`);

    return filterByDateRange(allVulns, startDate, endDate);
};

/**
 * Filter vulnerabilities by date range
 */
const filterByDateRange = (vulns, startDate, endDate) => {
    const startTime = startDate.getTime();
    const endTime = endDate.getTime();

    return vulns.filter(vuln => {
        const published = vuln.published ? new Date(vuln.published).getTime() : 0;
        return published >= startTime && published <= endTime;
    });
};

/**
 * Clear the Mozilla cache
 */
export const clearMozillaCache = () => {
    mozillaCache.data = null;
    mozillaCache.fetchedAt = null;
};

export default {
    fetchMozillaVulnerabilities,
    clearMozillaCache
};
