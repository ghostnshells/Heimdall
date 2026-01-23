// CISA Known Exploited Vulnerabilities (KEV) Catalog API
// Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
// This is a free, authoritative source for actively exploited vulnerabilities

// Use Vite proxy to bypass CORS in development
const CISA_KEV_URL = '/api/cisa/known_exploited_vulnerabilities.json';

// Cache for CISA data (refreshed every hour)
let cachedData = null;
let cacheTimestamp = 0;
const CACHE_DURATION = 60 * 60 * 1000; // 1 hour

/**
 * Fetch the full CISA KEV catalog
 * @returns {Promise<Array>} Array of known exploited vulnerabilities
 */
export const fetchCISAKEV = async () => {
    const now = Date.now();

    // Return cached data if valid
    if (cachedData && (now - cacheTimestamp) < CACHE_DURATION) {
        return cachedData;
    }

    try {
        const response = await fetch(CISA_KEV_URL);

        if (!response.ok) {
            throw new Error(`CISA API error: ${response.status}`);
        }

        const data = await response.json();
        cachedData = data.vulnerabilities || [];
        cacheTimestamp = now;

        console.log(`Fetched ${cachedData.length} vulnerabilities from CISA KEV`);
        return cachedData;
    } catch (error) {
        // CISA fetch may fail due to CORS/network issues - this is non-critical
        // NVD is the primary data source
        console.debug('CISA KEV fetch unavailable (non-critical):', error.message);
        return cachedData || []; // Return stale cache if available
    }
};

/**
 * Search CISA KEV for vulnerabilities matching an asset
 * @param {Object} asset - Asset object with keywords
 * @param {Date} startDate - Start of date range
 * @param {Date} endDate - End of date range
 * @returns {Promise<Array>} Matching vulnerabilities
 */
export const searchCISAForAsset = async (asset, startDate, endDate) => {
    const allVulns = await fetchCISAKEV();

    if (!allVulns.length) {
        return [];
    }

    // Build search terms from asset
    const searchTerms = [
        asset.vendor?.toLowerCase(),
        asset.name?.toLowerCase(),
        ...(asset.keywords || []).map(k => k.toLowerCase())
    ].filter(Boolean);

    // Filter vulnerabilities that match the asset and date range
    const matches = allVulns.filter(vuln => {
        // Check date range
        const dateAdded = new Date(vuln.dateAdded);
        if (dateAdded < startDate || dateAdded > endDate) {
            return false;
        }

        // Check if vendor or product matches
        const vulnVendor = vuln.vendorProject?.toLowerCase() || '';
        const vulnProduct = vuln.product?.toLowerCase() || '';
        const vulnName = vuln.vulnerabilityName?.toLowerCase() || '';

        return searchTerms.some(term =>
            vulnVendor.includes(term) ||
            vulnProduct.includes(term) ||
            vulnName.includes(term)
        );
    });

    // Transform to our standard format
    return matches.map(vuln => ({
        id: vuln.cveID,
        published: vuln.dateAdded,
        lastModified: vuln.dateAdded,
        description: vuln.shortDescription || vuln.vulnerabilityName,
        cvssScore: null, // CISA doesn't provide CVSS scores
        severity: 'HIGH', // All KEV entries are considered high priority
        cvssVector: null,
        references: [
            {
                url: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`,
                source: 'NVD',
                tags: ['Reference']
            },
            {
                url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${vuln.cveID}`,
                source: 'CISA',
                tags: ['Vendor Advisory']
            }
        ],
        affectedProducts: [{
            vendor: vuln.vendorProject,
            product: vuln.product
        }],
        source: 'CISA KEV',
        cisaData: {
            vendorProject: vuln.vendorProject,
            product: vuln.product,
            vulnerabilityName: vuln.vulnerabilityName,
            dateAdded: vuln.dateAdded,
            dueDate: vuln.dueDate,
            requiredAction: vuln.requiredAction,
            knownRansomwareCampaignUse: vuln.knownRansomwareCampaignUse
        },
        // Mark as actively exploited
        activelyExploited: true
    }));
};

export default {
    fetchCISAKEV,
    searchCISAForAsset
};
