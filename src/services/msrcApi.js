/**
 * Microsoft Security Response Center (MSRC) API Service
 * Fetches security advisories directly from Microsoft
 * API Docs: https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API
 *
 * Benefits over NVD:
 * - Publishes advisories 24-72 hours before NVD adds CPE data
 * - Includes Microsoft-specific severity ratings
 * - Direct from the source
 */

const MSRC_API_BASE = 'https://api.msrc.microsoft.com/cvrf/v3.0';

// Cache for MSRC data
let msrcCache = {
    data: null,
    fetchedAt: null,
    cacheMs: 60 * 60 * 1000 // 1 hour cache
};

/**
 * Get the current and previous month in YYYY-Mon format for MSRC API
 */
const getRecentMonths = (numMonths = 3) => {
    const months = [];
    const now = new Date();

    for (let i = 0; i < numMonths; i++) {
        const date = new Date(now.getFullYear(), now.getMonth() - i, 1);
        const year = date.getFullYear();
        const month = date.toLocaleString('en-US', { month: 'short' });
        months.push(`${year}-${month}`);
    }

    return months;
};

/**
 * Fetch MSRC updates for a specific month
 * @param {string} monthYear - Format: "2026-Jan"
 */
const fetchMSRCMonth = async (monthYear) => {
    try {
        const response = await fetch(`${MSRC_API_BASE}/cvrf/${monthYear}`, {
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            if (response.status === 404) {
                // No updates for this month yet
                return [];
            }
            throw new Error(`MSRC API error: ${response.status}`);
        }

        const data = await response.json();
        return parseMSRCResponse(data, monthYear);
    } catch (error) {
        console.error(`[MSRC API] Error fetching ${monthYear}:`, error.message);
        return [];
    }
};

/**
 * Parse MSRC CVRF response into normalized vulnerability format
 */
const parseMSRCResponse = (data, monthYear) => {
    const vulnerabilities = [];

    if (!data.Vulnerability) {
        return vulnerabilities;
    }

    data.Vulnerability.forEach(vuln => {
        // Get CVE ID
        const cveId = vuln.CVE;
        if (!cveId || !cveId.startsWith('CVE-')) {
            return;
        }

        // Get description
        const description = vuln.Notes?.find(n => n.Type === 1)?.Value ||
                           vuln.Title?.Value ||
                           'No description available';

        // Get CVSS score from threats/scores
        let cvssScore = null;
        let severity = 'UNKNOWN';

        if (vuln.CVSSScoreSets) {
            const scoreSet = vuln.CVSSScoreSets[0];
            if (scoreSet?.BaseScore) {
                cvssScore = parseFloat(scoreSet.BaseScore);
                severity = getSeverityFromScore(cvssScore);
            }
        }

        // Get affected products
        const affectedProducts = [];
        if (vuln.ProductStatuses) {
            vuln.ProductStatuses.forEach(status => {
                if (status.ProductID) {
                    status.ProductID.forEach(productId => {
                        // Look up product name from document
                        const productName = data.ProductTree?.FullProductName?.find(
                            p => p.ProductID === productId
                        )?.Value || productId;

                        affectedProducts.push({
                            product: productName,
                            vendor: 'Microsoft'
                        });
                    });
                }
            });
        }

        // Get references
        const references = [];
        if (vuln.References) {
            vuln.References.forEach(ref => {
                if (ref.URL) {
                    references.push({
                        url: ref.URL,
                        source: ref.Description?.Value || 'Microsoft',
                        tags: ref.Type === 'External' ? ['Third Party Advisory'] : ['Vendor Advisory']
                    });
                }
            });
        }

        // Get dates - MSRC uses revision history
        let published = null;
        let lastModified = null;

        if (vuln.RevisionHistory) {
            const revisions = vuln.RevisionHistory.sort((a, b) =>
                new Date(a.Date) - new Date(b.Date)
            );
            if (revisions.length > 0) {
                published = revisions[0].Date;
                lastModified = revisions[revisions.length - 1].Date;
            }
        }

        // Fallback to document tracking dates
        if (!published && data.DocumentTracking?.InitialReleaseDate) {
            published = data.DocumentTracking.InitialReleaseDate;
        }
        if (!lastModified && data.DocumentTracking?.CurrentReleaseDate) {
            lastModified = data.DocumentTracking.CurrentReleaseDate;
        }

        vulnerabilities.push({
            id: cveId,
            source: 'MSRC',
            published,
            lastModified,
            description: cleanDescription(description),
            cvssScore,
            severity,
            affectedProducts: affectedProducts.slice(0, 10), // Limit to avoid bloat
            references,
            msrcData: {
                title: vuln.Title?.Value,
                monthYear
            }
        });
    });

    return vulnerabilities;
};

/**
 * Clean HTML and excessive whitespace from description
 */
const cleanDescription = (desc) => {
    if (!desc) return '';
    return desc
        .replace(/<[^>]*>/g, '') // Remove HTML tags
        .replace(/\s+/g, ' ')    // Normalize whitespace
        .trim()
        .substring(0, 1000);     // Limit length
};

/**
 * Get severity from CVSS score
 */
const getSeverityFromScore = (score) => {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score >= 0.1) return 'LOW';
    return 'NONE';
};

/**
 * Fetch Microsoft vulnerabilities for a date range
 * @param {Date} startDate
 * @param {Date} endDate
 */
export const fetchMicrosoftVulnerabilities = async (startDate, endDate) => {
    // Check cache
    if (msrcCache.data && msrcCache.fetchedAt &&
        (Date.now() - msrcCache.fetchedAt) < msrcCache.cacheMs) {
        console.log('[MSRC API] Using cached data');
        return filterByDateRange(msrcCache.data, startDate, endDate);
    }

    console.log('[MSRC API] Fetching Microsoft security updates...');

    // Fetch last 3 months of updates
    const months = getRecentMonths(3);
    const allVulns = [];

    for (const month of months) {
        const vulns = await fetchMSRCMonth(month);
        allVulns.push(...vulns);

        // Small delay to be nice to the API
        await new Promise(resolve => setTimeout(resolve, 500));
    }

    // Update cache
    msrcCache.data = allVulns;
    msrcCache.fetchedAt = Date.now();

    console.log(`[MSRC API] Fetched ${allVulns.length} Microsoft vulnerabilities`);

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
 * Clear the MSRC cache
 */
export const clearMSRCCache = () => {
    msrcCache.data = null;
    msrcCache.fetchedAt = null;
};

export default {
    fetchMicrosoftVulnerabilities,
    clearMSRCCache
};
