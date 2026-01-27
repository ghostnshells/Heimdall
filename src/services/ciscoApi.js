/**
 * Cisco PSIRT openVuln API Service
 * Fetches security advisories directly from Cisco
 * API Docs: https://developer.cisco.com/psirt/
 *
 * Benefits over NVD:
 * - Real-time updates from Cisco PSIRT
 * - Includes Cisco-specific impact ratings and bug IDs
 * - Maps to specific IOS/IOS-XE versions
 *
 * Note: Requires OAuth2 credentials from Cisco DevNet
 * Get credentials at: https://developer.cisco.com/
 */

// API endpoints
const CISCO_TOKEN_URL = 'https://id.cisco.com/oauth2/default/v1/token';
const CISCO_API_BASE = 'https://apix.cisco.com/security/advisories/v2';

// Cache for Cisco data and token
let ciscoCache = {
    data: null,
    fetchedAt: null,
    cacheMs: 60 * 60 * 1000, // 1 hour cache
    accessToken: null,
    tokenExpiry: null
};

// Get credentials from environment
const getCredentials = () => {
    const clientId = import.meta.env.VITE_CISCO_CLIENT_ID || '';
    const clientSecret = import.meta.env.VITE_CISCO_CLIENT_SECRET || '';
    return { clientId, clientSecret };
};

/**
 * Get OAuth2 access token from Cisco
 */
const getAccessToken = async () => {
    // Check if we have a valid token
    if (ciscoCache.accessToken && ciscoCache.tokenExpiry &&
        Date.now() < ciscoCache.tokenExpiry) {
        return ciscoCache.accessToken;
    }

    const { clientId, clientSecret } = getCredentials();

    if (!clientId || !clientSecret) {
        console.warn('[Cisco API] No credentials configured. Set VITE_CISCO_CLIENT_ID and VITE_CISCO_CLIENT_SECRET');
        return null;
    }

    try {
        const response = await fetch(CISCO_TOKEN_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'client_credentials',
                client_id: clientId,
                client_secret: clientSecret
            })
        });

        if (!response.ok) {
            throw new Error(`Token request failed: ${response.status}`);
        }

        const data = await response.json();
        ciscoCache.accessToken = data.access_token;
        // Token usually valid for 1 hour, refresh 5 minutes early
        ciscoCache.tokenExpiry = Date.now() + ((data.expires_in - 300) * 1000);

        return ciscoCache.accessToken;
    } catch (error) {
        console.error('[Cisco API] Failed to get access token:', error.message);
        return null;
    }
};

/**
 * Fetch advisories from Cisco API
 */
const fetchCiscoAdvisories = async (endpoint) => {
    const token = await getAccessToken();

    if (!token) {
        return [];
    }

    try {
        const response = await fetch(`${CISCO_API_BASE}${endpoint}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            throw new Error(`Cisco API error: ${response.status}`);
        }

        const data = await response.json();
        return data.advisories || [];
    } catch (error) {
        console.error(`[Cisco API] Error fetching ${endpoint}:`, error.message);
        return [];
    }
};

/**
 * Parse Cisco advisory into normalized vulnerability format
 */
const parseCiscoAdvisory = (advisory) => {
    // Get CVE IDs (can have multiple)
    const cves = advisory.cves || [];
    if (cves.length === 0) {
        return null;
    }

    // Get severity
    let severity = 'UNKNOWN';
    let cvssScore = null;

    if (advisory.sir) {
        // Cisco Security Impact Rating
        const sirMap = {
            'Critical': 'CRITICAL',
            'High': 'HIGH',
            'Medium': 'MEDIUM',
            'Low': 'LOW',
            'Informational': 'NONE'
        };
        severity = sirMap[advisory.sir] || 'UNKNOWN';
    }

    if (advisory.cvssBaseScore) {
        cvssScore = parseFloat(advisory.cvssBaseScore);
    }

    // Get affected products
    const affectedProducts = [];
    if (advisory.productNames) {
        advisory.productNames.forEach(product => {
            affectedProducts.push({
                product: product,
                vendor: 'Cisco',
                cpe: `cpe:2.3:*:cisco:${product.toLowerCase().replace(/\s+/g, '_')}:*:*:*:*:*:*:*:*`
            });
        });
    }

    // Build references
    const references = [];

    // Main advisory URL
    if (advisory.publicationUrl) {
        references.push({
            url: advisory.publicationUrl,
            source: 'Cisco',
            tags: ['Vendor Advisory']
        });
    }

    // Bug IDs link to Cisco Bug Search
    if (advisory.bugIDs) {
        advisory.bugIDs.forEach(bugId => {
            references.push({
                url: `https://bst.cloudapps.cisco.com/bugsearch/bug/${bugId}`,
                source: 'Cisco Bug Search',
                tags: ['Issue Tracking']
            });
        });
    }

    // Return one vulnerability per CVE
    return cves.map(cve => ({
        id: cve,
        source: 'Cisco PSIRT',
        published: advisory.firstPublished,
        lastModified: advisory.lastUpdated,
        description: advisory.summary || advisory.headline || 'No description available',
        cvssScore,
        severity,
        affectedProducts,
        references,
        ciscoData: {
            advisoryId: advisory.advisoryId,
            advisoryTitle: advisory.advisoryTitle,
            sir: advisory.sir,
            bugIDs: advisory.bugIDs,
            cwe: advisory.cwe,
            ipsSignatures: advisory.ipsSignatures
        }
    }));
};

/**
 * Fetch Cisco vulnerabilities for a date range
 * @param {Date} startDate
 * @param {Date} endDate
 */
export const fetchCiscoVulnerabilities = async (startDate, endDate) => {
    // Check cache
    if (ciscoCache.data && ciscoCache.fetchedAt &&
        (Date.now() - ciscoCache.fetchedAt) < ciscoCache.cacheMs) {
        console.log('[Cisco API] Using cached data');
        return filterByDateRange(ciscoCache.data, startDate, endDate);
    }

    const { clientId, clientSecret } = getCredentials();

    if (!clientId || !clientSecret) {
        console.log('[Cisco API] Skipping - no credentials configured');
        return [];
    }

    console.log('[Cisco API] Fetching Cisco security advisories...');

    // Format dates for API
    const formatDate = (date) => date.toISOString().split('T')[0];
    const startStr = formatDate(startDate);
    const endStr = formatDate(endDate);

    // Fetch advisories by date range
    const advisories = await fetchCiscoAdvisories(
        `/all?startDate=${startStr}&endDate=${endStr}`
    );

    // Parse all advisories
    const allVulns = [];
    advisories.forEach(advisory => {
        const vulns = parseCiscoAdvisory(advisory);
        if (vulns) {
            allVulns.push(...vulns);
        }
    });

    // Deduplicate by CVE ID
    const seen = new Set();
    const uniqueVulns = allVulns.filter(vuln => {
        if (seen.has(vuln.id)) {
            return false;
        }
        seen.add(vuln.id);
        return true;
    });

    // Update cache
    ciscoCache.data = uniqueVulns;
    ciscoCache.fetchedAt = Date.now();

    console.log(`[Cisco API] Fetched ${uniqueVulns.length} Cisco vulnerabilities`);

    return filterByDateRange(uniqueVulns, startDate, endDate);
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
 * Check if Cisco API is configured
 */
export const isCiscoApiConfigured = () => {
    const { clientId, clientSecret } = getCredentials();
    return !!(clientId && clientSecret);
};

/**
 * Clear the Cisco cache
 */
export const clearCiscoCache = () => {
    ciscoCache.data = null;
    ciscoCache.fetchedAt = null;
};

export default {
    fetchCiscoVulnerabilities,
    isCiscoApiConfigured,
    clearCiscoCache
};
