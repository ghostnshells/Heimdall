/**
 * GitHub Advisory Database Service
 * Fetches security advisories from GitHub's global advisory database
 * API Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
 *
 * Benefits over NVD:
 * - Often has advisories before NVD (especially for open-source)
 * - Includes GHSA IDs that may not have CVE yet
 * - Good coverage for software dependencies
 * - Free API (no auth required for public advisories)
 */

const GITHUB_API_BASE = 'https://api.github.com/advisories';

// Cache for GitHub data
let githubCache = {
    data: null,
    fetchedAt: null,
    cacheMs: 30 * 60 * 1000 // 30 minute cache (GitHub rate limits unauthenticated requests)
};

// Ecosystems relevant to our monitored assets
const RELEVANT_ECOSYSTEMS = [
    'npm',        // Node.js packages
    'nuget',      // .NET packages (Microsoft)
    'pip',        // Python packages
    'maven',      // Java packages
    'go',         // Go packages
    'rubygems',   // Ruby packages
    'composer',   // PHP packages
    'actions'     // GitHub Actions
];

// Map GitHub severity to standard format
const severityMap = {
    'critical': 'CRITICAL',
    'high': 'HIGH',
    'moderate': 'MEDIUM',
    'medium': 'MEDIUM',
    'low': 'LOW',
    'unknown': 'UNKNOWN'
};

/**
 * Fetch advisories from GitHub API
 * @param {Object} params - Query parameters
 */
const fetchGitHubAdvisories = async (params = {}) => {
    const queryParams = new URLSearchParams({
        per_page: '100',
        ...params
    });

    try {
        const response = await fetch(`${GITHUB_API_BASE}?${queryParams}`, {
            headers: {
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'
            }
        });

        if (!response.ok) {
            if (response.status === 403) {
                console.warn('[GitHub API] Rate limited. Try again later or use a PAT.');
                return [];
            }
            throw new Error(`GitHub API error: ${response.status}`);
        }

        return await response.json();
    } catch (error) {
        console.error('[GitHub API] Error fetching advisories:', error.message);
        return [];
    }
};

/**
 * Parse GitHub advisory into normalized vulnerability format
 */
const parseGitHubAdvisory = (advisory) => {
    // Get CVE ID or GHSA ID
    const cveId = advisory.cve_id || advisory.ghsa_id;
    if (!cveId) {
        return null;
    }

    // Get CVSS score and severity
    let cvssScore = null;
    let severity = severityMap[advisory.severity?.toLowerCase()] || 'UNKNOWN';

    if (advisory.cvss?.score) {
        cvssScore = parseFloat(advisory.cvss.score);
    }

    // Get affected products/packages
    const affectedProducts = [];
    if (advisory.vulnerabilities) {
        advisory.vulnerabilities.forEach(vuln => {
            if (vuln.package) {
                affectedProducts.push({
                    product: vuln.package.name,
                    vendor: vuln.package.ecosystem,
                    ecosystem: vuln.package.ecosystem,
                    vulnerableVersionRange: vuln.vulnerable_version_range,
                    patchedVersions: vuln.patched_versions,
                    firstPatchedVersion: vuln.first_patched_version
                });
            }
        });
    }

    // Build references
    const references = [];

    // Add GitHub advisory URL
    if (advisory.html_url) {
        references.push({
            url: advisory.html_url,
            source: 'GitHub Advisory',
            tags: ['Vendor Advisory']
        });
    }

    // Add other references
    if (advisory.references) {
        advisory.references.forEach(ref => {
            references.push({
                url: ref,
                source: getSourceFromUrl(ref),
                tags: ['Reference']
            });
        });
    }

    // Add NVD reference if it's a CVE
    if (cveId.startsWith('CVE-')) {
        references.push({
            url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
            source: 'NVD',
            tags: ['Reference']
        });
    }

    return {
        id: cveId,
        source: 'GitHub Advisory',
        published: advisory.published_at,
        lastModified: advisory.updated_at,
        description: advisory.summary || advisory.description || 'No description available',
        cvssScore,
        severity,
        affectedProducts,
        references,
        githubData: {
            ghsaId: advisory.ghsa_id,
            cveId: advisory.cve_id,
            type: advisory.type,
            sourceCodeLocation: advisory.source_code_location,
            cwes: advisory.cwes?.map(cwe => cwe.cwe_id),
            credits: advisory.credits?.map(c => c.user?.login)
        }
    };
};

/**
 * Get source name from URL
 */
const getSourceFromUrl = (url) => {
    try {
        const hostname = new URL(url).hostname;
        return hostname.replace('www.', '');
    } catch {
        return 'Unknown';
    }
};

/**
 * Fetch GitHub advisories for a date range, optionally filtered by ecosystem
 * @param {Date} startDate
 * @param {Date} endDate
 * @param {string[]} ecosystems - Optional ecosystems to filter
 */
export const fetchGitHubVulnerabilities = async (startDate, endDate, ecosystems = null) => {
    // Check cache
    if (githubCache.data && githubCache.fetchedAt &&
        (Date.now() - githubCache.fetchedAt) < githubCache.cacheMs) {
        console.log('[GitHub API] Using cached data');
        return filterByDateRange(githubCache.data, startDate, endDate);
    }

    console.log('[GitHub API] Fetching GitHub security advisories...');

    // Format dates for API
    const formatDate = (date) => date.toISOString();

    // Build query params
    const params = {
        type: 'reviewed', // Only get reviewed advisories (more reliable)
        published: `${formatDate(startDate)}..${formatDate(endDate)}`
    };

    // Fetch advisories
    const advisories = await fetchGitHubAdvisories(params);

    // Parse all advisories
    const allVulns = [];
    advisories.forEach(advisory => {
        const vuln = parseGitHubAdvisory(advisory);
        if (vuln) {
            allVulns.push(vuln);
        }
    });

    // Update cache
    githubCache.data = allVulns;
    githubCache.fetchedAt = Date.now();

    console.log(`[GitHub API] Fetched ${allVulns.length} GitHub advisories`);

    return filterByDateRange(allVulns, startDate, endDate);
};

/**
 * Fetch advisories relevant to specific vendors/products
 * This is useful for finding advisories that affect dependencies of our monitored products
 * @param {string} keyword - Search keyword
 * @param {Date} startDate
 * @param {Date} endDate
 */
export const searchGitHubAdvisories = async (keyword, startDate, endDate) => {
    console.log(`[GitHub API] Searching for advisories matching "${keyword}"...`);

    // Note: GitHub's search is limited, so we'll filter from cached data
    const allVulns = await fetchGitHubVulnerabilities(startDate, endDate);

    const keywordLower = keyword.toLowerCase();

    return allVulns.filter(vuln => {
        // Check description
        if (vuln.description?.toLowerCase().includes(keywordLower)) {
            return true;
        }
        // Check affected products
        if (vuln.affectedProducts?.some(p =>
            p.product?.toLowerCase().includes(keywordLower) ||
            p.vendor?.toLowerCase().includes(keywordLower)
        )) {
            return true;
        }
        return false;
    });
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
 * Clear the GitHub cache
 */
export const clearGitHubCache = () => {
    githubCache.data = null;
    githubCache.fetchedAt = null;
};

export default {
    fetchGitHubVulnerabilities,
    searchGitHubAdvisories,
    clearGitHubCache
};
