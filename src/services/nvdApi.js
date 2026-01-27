// NVD (National Vulnerability Database) API Service
// Documentation: https://nvd.nist.gov/developers/vulnerabilities

// Use Vite proxy to bypass CORS in development
// In production, you would use a backend proxy or serverless function
const NVD_API_BASE = '/api/nvd';

// NVD API Key - loaded from environment variable (NEVER hardcode API keys!)
// In development, requests go through Vite proxy without auth (lower rate limit)
// In production, all requests go through the backend which has the API key
const NVD_API_KEY = import.meta.env.VITE_NVD_API_KEY || '';

// Rate limiting configuration:
// - WITH API key: 50 requests per 30 seconds = 600ms minimum delay (using 800ms to be safe)
// - WITHOUT API key: 5 requests per 30 seconds = 6000ms minimum delay (using 6500ms to be safe)
let lastRequestTime = 0;
let consecutiveErrors = 0;
const REQUEST_DELAY_WITH_KEY = 800;    // 0.8 seconds with API key
const REQUEST_DELAY_NO_KEY = 6500;     // 6.5 seconds without API key (NVD enforces 5 requests/30 sec)
const MAX_RETRY_DELAY = 60000;         // Max 60 seconds between retries after errors

// Get dynamic delay based on API key presence and error state
const getRequestDelay = () => {
    const baseDelay = NVD_API_KEY ? REQUEST_DELAY_WITH_KEY : REQUEST_DELAY_NO_KEY;
    // Exponential backoff on consecutive errors
    if (consecutiveErrors > 0) {
        const backoffDelay = Math.min(baseDelay * Math.pow(2, consecutiveErrors), MAX_RETRY_DELAY);
        console.log(`[NVD API] Using backoff delay: ${backoffDelay}ms (${consecutiveErrors} consecutive errors)`);
        return backoffDelay;
    }
    return baseDelay;
};

const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const enforceRateLimit = async () => {
    const now = Date.now();
    const timeSinceLastRequest = now - lastRequestTime;
    const requiredDelay = getRequestDelay();

    if (timeSinceLastRequest < requiredDelay) {
        const waitTime = requiredDelay - timeSinceLastRequest;
        console.log(`[NVD API] Rate limiting: waiting ${waitTime}ms before next request`);
        await wait(waitTime);
    }

    lastRequestTime = Date.now();
};

// Reset error counter on successful request
const recordSuccess = () => {
    if (consecutiveErrors > 0) {
        console.log(`[NVD API] Request successful, resetting error counter`);
        consecutiveErrors = 0;
    }
};

// Increment error counter on failed request
const recordError = () => {
    consecutiveErrors++;
    console.warn(`[NVD API] Request failed, consecutive errors: ${consecutiveErrors}`);
};

/**
 * Search NVD for vulnerabilities matching keywords (by publication date)
 * @param {string} keyword - Search keyword
 * @param {Date} startDate - Start date for published date range
 * @param {Date} endDate - End date for published date range
 * @param {number} resultsPerPage - Max results to return
 * @returns {Promise<Array>} Array of CVE objects
 */
export const searchNVDByKeyword = async (keyword, startDate = null, endDate = null, resultsPerPage = 20) => {
    await enforceRateLimit();

    const params = new URLSearchParams({
        keywordSearch: keyword,
        resultsPerPage: resultsPerPage.toString()
    });

    if (startDate) {
        params.append('pubStartDate', startDate.toISOString());
    }
    if (endDate) {
        params.append('pubEndDate', endDate.toISOString());
    }

    try {
        const headers = {};
        if (NVD_API_KEY) {
            headers['apiKey'] = NVD_API_KEY;
        }

        const response = await fetch(`${NVD_API_BASE}?${params}`, { headers });

        if (!response.ok) {
            // Handle rate limiting specifically
            if (response.status === 429 || response.status === 403) {
                recordError();
                console.warn(`[NVD API] Rate limited (${response.status}) for keyword "${keyword}", will retry with longer delay`);
                // Wait and retry once
                await wait(getRequestDelay());
                const retryResponse = await fetch(`${NVD_API_BASE}?${params}`, { headers });
                if (retryResponse.ok) {
                    recordSuccess();
                    const data = await retryResponse.json();
                    return parseCVEResponse(data);
                }
            }
            throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
        }

        recordSuccess();
        const data = await response.json();
        return parseCVEResponse(data);
    } catch (error) {
        recordError();
        console.error(`Error fetching from NVD for keyword "${keyword}":`, error);
        return [];
    }
};

/**
 * Search NVD for vulnerabilities matching keywords (by last modified date)
 * @param {string} keyword - Search keyword
 * @param {Date} startDate - Start date for last modified range
 * @param {Date} endDate - End date for last modified range
 * @param {number} resultsPerPage - Max results to return
 * @returns {Promise<Array>} Array of CVE objects
 */
export const searchNVDByKeywordLastModified = async (keyword, startDate = null, endDate = null, resultsPerPage = 20) => {
    await enforceRateLimit();

    const params = new URLSearchParams({
        keywordSearch: keyword,
        resultsPerPage: resultsPerPage.toString()
    });

    if (startDate) {
        params.append('lastModStartDate', startDate.toISOString());
    }
    if (endDate) {
        params.append('lastModEndDate', endDate.toISOString());
    }

    try {
        const headers = {};
        if (NVD_API_KEY) {
            headers['apiKey'] = NVD_API_KEY;
        }

        const response = await fetch(`${NVD_API_BASE}?${params}`, { headers });

        if (!response.ok) {
            // Handle rate limiting specifically
            if (response.status === 429 || response.status === 403) {
                recordError();
                console.warn(`[NVD API] Rate limited (${response.status}) for keyword "${keyword}" (lastMod), will retry`);
                await wait(getRequestDelay());
                const retryResponse = await fetch(`${NVD_API_BASE}?${params}`, { headers });
                if (retryResponse.ok) {
                    recordSuccess();
                    const data = await retryResponse.json();
                    const results = parseCVEResponse(data);
                    return results.map(r => ({ ...r, recentlyModified: true }));
                }
            }
            throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
        }

        recordSuccess();
        const data = await response.json();
        const results = parseCVEResponse(data);
        return results.map(r => ({ ...r, recentlyModified: true }));
    } catch (error) {
        recordError();
        console.error(`Error fetching modified CVEs from NVD for keyword "${keyword}":`, error);
        return [];
    }
};

/**
 * Search NVD by CPE (Common Platform Enumeration) using publication date
 * @param {string} vendor - Vendor name
 * @param {string} product - Product name
 * @param {Date} startDate - Start date
 * @param {Date} endDate - End date
 * @param {number} resultsPerPage - Max results
 * @returns {Promise<Array>} Array of CVE objects
 */
export const searchNVDByCPE = async (vendor, product, startDate = null, endDate = null, resultsPerPage = 20) => {
    await enforceRateLimit();

    // Build virtual match string for CPE 2.3
    const cpeMatch = `cpe:2.3:*:${vendor}:${product}:*:*:*:*:*:*:*:*`;

    const params = new URLSearchParams({
        virtualMatchString: cpeMatch,
        resultsPerPage: resultsPerPage.toString()
    });

    if (startDate) {
        params.append('pubStartDate', startDate.toISOString());
    }
    if (endDate) {
        params.append('pubEndDate', endDate.toISOString());
    }

    try {
        const url = `${NVD_API_BASE}?${params}`;
        console.log(`[NVD API] CPE search: ${vendor}:${product}, resultsPerPage=${resultsPerPage}`);

        const headers = {};
        if (NVD_API_KEY) {
            headers['apiKey'] = NVD_API_KEY;
        }

        const response = await fetch(url, { headers });

        if (!response.ok) {
            // Handle rate limiting specifically
            if (response.status === 429 || response.status === 403) {
                recordError();
                console.warn(`[NVD API] Rate limited (${response.status}) for CPE ${vendor}:${product}, will retry with longer delay`);
                await wait(getRequestDelay());
                const retryResponse = await fetch(url, { headers });
                if (retryResponse.ok) {
                    recordSuccess();
                    const data = await retryResponse.json();
                    console.log(`[NVD API] ${vendor}:${product} (retry) returned ${data.totalResults || 0} total results`);
                    return parseCVEResponse(data);
                }
            }
            const errorText = await response.text();
            console.error(`[NVD API] Error response:`, errorText);
            throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
        }

        recordSuccess();
        const data = await response.json();
        console.log(`[NVD API] ${vendor}:${product} returned ${data.totalResults || 0} total results, got ${data.vulnerabilities?.length || 0} in this page`);
        return parseCVEResponse(data);
    } catch (error) {
        recordError();
        console.error(`[NVD API] Error fetching for CPE "${vendor}:${product}":`, error);
        return [];
    }
};

/**
 * Search NVD by CPE using last modified date (for catching updated vulnerabilities)
 * @param {string} vendor - Vendor name
 * @param {string} product - Product name
 * @param {Date} startDate - Start date for last modified range
 * @param {Date} endDate - End date for last modified range
 * @param {number} resultsPerPage - Max results
 * @returns {Promise<Array>} Array of CVE objects
 */
export const searchNVDByCPELastModified = async (vendor, product, startDate = null, endDate = null, resultsPerPage = 20) => {
    await enforceRateLimit();

    // Build virtual match string for CPE 2.3
    const cpeMatch = `cpe:2.3:*:${vendor}:${product}:*:*:*:*:*:*:*:*`;

    const params = new URLSearchParams({
        virtualMatchString: cpeMatch,
        resultsPerPage: resultsPerPage.toString()
    });

    // Use lastMod dates instead of pub dates
    if (startDate) {
        params.append('lastModStartDate', startDate.toISOString());
    }
    if (endDate) {
        params.append('lastModEndDate', endDate.toISOString());
    }

    try {
        console.log(`[NVD API] CPE lastMod search: ${vendor}:${product}, resultsPerPage=${resultsPerPage}`);

        const headers = {};
        if (NVD_API_KEY) {
            headers['apiKey'] = NVD_API_KEY;
        }

        const url = `${NVD_API_BASE}?${params}`;
        const response = await fetch(url, { headers });

        if (!response.ok) {
            // Handle rate limiting specifically
            if (response.status === 429 || response.status === 403) {
                recordError();
                console.warn(`[NVD API] Rate limited (${response.status}) for CPE ${vendor}:${product} (lastMod), will retry`);
                await wait(getRequestDelay());
                const retryResponse = await fetch(url, { headers });
                if (retryResponse.ok) {
                    recordSuccess();
                    const data = await retryResponse.json();
                    console.log(`[NVD API] ${vendor}:${product} (lastMod retry) returned ${data.totalResults || 0} total results`);
                    const results = parseCVEResponse(data);
                    return results.map(r => ({ ...r, recentlyModified: true }));
                }
            }
            const errorText = await response.text();
            console.error(`[NVD API] Error response:`, errorText);
            throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
        }

        recordSuccess();
        const data = await response.json();
        console.log(`[NVD API] ${vendor}:${product} (lastMod) returned ${data.totalResults || 0} total results, got ${data.vulnerabilities?.length || 0} in this page`);
        const results = parseCVEResponse(data);
        // Mark these as recently modified
        return results.map(r => ({ ...r, recentlyModified: true }));
    } catch (error) {
        recordError();
        console.error(`[NVD API] Error fetching modified CVEs for CPE "${vendor}:${product}":`, error);
        return [];
    }
};

/**
 * Parse NVD API response into standardized CVE objects
 */
const parseCVEResponse = (data) => {
    if (!data.vulnerabilities || !Array.isArray(data.vulnerabilities)) {
        return [];
    }

    return data.vulnerabilities.map(vuln => {
        const cve = vuln.cve;

        // Get CVSS score - try v3.1, then v3.0, then v2
        let cvssScore = null;
        let severity = 'UNKNOWN';
        let cvssVector = null;

        if (cve.metrics?.cvssMetricV31?.[0]) {
            const metric = cve.metrics.cvssMetricV31[0];
            cvssScore = metric.cvssData?.baseScore;
            severity = metric.cvssData?.baseSeverity || getSeverityFromScore(cvssScore);
            cvssVector = metric.cvssData?.vectorString;
        } else if (cve.metrics?.cvssMetricV30?.[0]) {
            const metric = cve.metrics.cvssMetricV30[0];
            cvssScore = metric.cvssData?.baseScore;
            severity = metric.cvssData?.baseSeverity || getSeverityFromScore(cvssScore);
            cvssVector = metric.cvssData?.vectorString;
        } else if (cve.metrics?.cvssMetricV2?.[0]) {
            const metric = cve.metrics.cvssMetricV2[0];
            cvssScore = metric.cvssData?.baseScore;
            severity = getSeverityFromScoreV2(cvssScore);
            cvssVector = metric.cvssData?.vectorString;
        }

        // Get description (prefer English)
        const description = cve.descriptions?.find(d => d.lang === 'en')?.value ||
            cve.descriptions?.[0]?.value ||
            'No description available';

        // Get references
        const references = cve.references?.map(ref => ({
            url: ref.url,
            source: ref.source,
            tags: ref.tags || []
        })) || [];

        // Get affected products from configurations
        const affectedProducts = [];
        if (cve.configurations) {
            cve.configurations.forEach(config => {
                config.nodes?.forEach(node => {
                    node.cpeMatch?.forEach(match => {
                        if (match.vulnerable) {
                            affectedProducts.push({
                                cpe: match.criteria,
                                versionStart: match.versionStartIncluding || match.versionStartExcluding,
                                versionEnd: match.versionEndIncluding || match.versionEndExcluding
                            });
                        }
                    });
                });
            });
        }

        return {
            id: cve.id,
            published: cve.published,
            lastModified: cve.lastModified,
            description,
            cvssScore,
            severity,
            cvssVector,
            references,
            affectedProducts,
            source: 'NVD'
        };
    });
};

/**
 * Get severity label from CVSS v3 score
 */
const getSeverityFromScore = (score) => {
    if (score === null || score === undefined) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score >= 0.1) return 'LOW';
    return 'NONE';
};

/**
 * Get severity label from CVSS v2 score
 */
const getSeverityFromScoreV2 = (score) => {
    if (score === null || score === undefined) return 'UNKNOWN';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
};

/**
 * Get the most recent date between published and lastModified for sorting
 * Returns the timestamp (milliseconds since epoch) for comparison
 */
const getMostRecentDate = (vuln) => {
    const published = vuln.published ? new Date(vuln.published).getTime() : 0;
    const lastModified = vuln.lastModified ? new Date(vuln.lastModified).getTime() : 0;
    return Math.max(published, lastModified);
};

/**
 * Sort vulnerabilities by most recent date (either published or lastModified)
 * Most recent first
 */
const sortByMostRecentDate = (vulnerabilities) => {
    return [...vulnerabilities].sort((a, b) => getMostRecentDate(b) - getMostRecentDate(a));
};

/**
 * Validate that a vulnerability's dates fall within the requested time range
 * This prevents old CVEs from appearing when they shouldn't
 * @param {Object} vuln - Vulnerability object
 * @param {Date} startDate - Start of the time range
 * @param {Date} endDate - End of the time range
 * @returns {boolean} True if the vulnerability is within the date range
 */
const isWithinDateRange = (vuln, startDate, endDate) => {
    const startTime = startDate.getTime();
    const endTime = endDate.getTime();

    const published = vuln.published ? new Date(vuln.published).getTime() : 0;

    // Only check published date - NVD's lastModified date reflects when NVD touched
    // the record (even for minor metadata changes like CPE updates), not when the
    // vulnerability was meaningfully updated. Using lastModified causes old CVEs
    // to appear with misleading "Modified" dates.
    return published >= startTime && published <= endTime;
};

/**
 * Deduplicate vulnerabilities by CVE ID, keeping the one with recentlyModified flag if present
 */
const deduplicateVulnerabilities = (vulnerabilities) => {
    const seen = new Map();
    vulnerabilities.forEach(vuln => {
        const existing = seen.get(vuln.id);
        if (!existing || vuln.recentlyModified) {
            seen.set(vuln.id, vuln);
        }
    });
    return Array.from(seen.values());
};

/**
 * Product-specific validation rules to filter out false positives
 * Returns true if the vulnerability is valid for the asset, false otherwise
 */
const PRODUCT_VALIDATORS = {
    // ==========================================
    // CISCO - Consolidated validator for Cisco software products
    // Monitors: IOS, IOS XE, IOS XR, ISE, Unified CM (software only - hardware rarely has CVEs)
    // ==========================================
    'cisco': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        // Must have Cisco CPE
        const hasCiscoCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':cisco:')
        );

        // Description must mention Cisco software context
        const descHasCiscoContext =
            desc.includes('cisco') ||
            desc.includes('ios-xe') ||
            desc.includes('ios-xr') ||
            desc.includes('identity services engine') ||
            desc.includes('unified communications manager') ||
            desc.includes('unified cm') ||
            desc.includes('cucm');

        // Exclude Apple iOS (common false positive)
        const isAppleIOS =
            desc.includes('apple ios') ||
            desc.includes('iphone') ||
            desc.includes('ipad') ||
            desc.includes('apple tv') ||
            desc.includes('watchos') ||
            (desc.includes('ios') && desc.includes('apple') && !desc.includes('cisco'));
        const hasAppleCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':apple:')
        );

        // Exclude other vendors' network equipment
        const otherVendorExclusions = [
            'juniper', 'arista', 'huawei', 'dell networking', 'hp procurve',
            'fortinet', 'palo alto', 'f5 big-ip'
        ];
        const hasOtherVendor = otherVendorExclusions.some(term => desc.includes(term));

        return (hasCiscoCPE || descHasCiscoContext) && !isAppleIOS && !hasAppleCPE && !hasOtherVendor;
    },

    // ==========================================
    // MICROSOFT - Consolidated validator for all Microsoft products
    // Monitors: Windows, Office 365, Exchange, SharePoint, SQL Server, Teams, Edge, Azure
    // ==========================================
    'microsoft': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        // Must have Microsoft CPE
        const hasMicrosoftCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':microsoft:')
        );

        // Description must mention Microsoft context
        const descHasMicrosoftContext =
            desc.includes('microsoft') ||
            desc.includes('windows') ||
            desc.includes('office 365') ||
            desc.includes('exchange server') ||
            desc.includes('sharepoint') ||
            desc.includes('sql server') ||
            desc.includes('azure') ||
            desc.includes('visual studio') ||
            desc.includes('edge chromium') ||
            desc.includes('teams');

        // Exclude other vendors' products
        const otherVendorExclusions = [
            'libreoffice', 'openoffice', 'google docs', 'google workspace',
            'linux', 'macos', 'apple'
        ];
        const hasOtherVendor = otherVendorExclusions.some(term => desc.includes(term));

        return (hasMicrosoftCPE || descHasMicrosoftContext) && !hasOtherVendor;
    },

    // ==========================================
    // HPE - Consolidated validator for all HPE products
    // Monitors: ProLiant, Nimble, Alletra, iLO, OneView
    // ==========================================
    'hpe': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        // Must have HPE or HP CPE
        const hasHPECPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':hpe:') ||
            p.cpe?.includes(':hp:') ||
            p.cpe?.includes(':hewlett_packard_enterprise:')
        );

        // Description must mention HPE context
        const descHasHPEContext =
            desc.includes('hpe') ||
            desc.includes('hewlett packard enterprise') ||
            desc.includes('proliant') ||
            desc.includes('nimble storage') ||
            desc.includes('alletra') ||
            desc.includes('integrated lights-out') ||
            desc.includes('integrated lights out') ||
            desc.includes('ilo 4') || desc.includes('ilo 5') || desc.includes('ilo 6') ||
            desc.includes('oneview') ||
            desc.includes('storeonce');

        // Explicit exclusions for common false positives
        const explicitExclusions = [
            'mongodb', 'mysql', 'postgresql', 'oracle database', 'sql server',
            'redis', 'cassandra', 'elasticsearch', 'aws', 'azure storage',
            'google cloud', 's3 bucket', 'minio', 'ceph',
            'dell', 'lenovo', 'supermicro', 'cisco ucs'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasHPECPE || descHasHPEContext) && !hasExcludedProduct;
    },

    // ==========================================
    // WatchGuard - Firewall and VPN products
    // ==========================================
    'watchguard': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasWatchGuardCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':watchguard:')
        );

        const descHasWatchGuardContext =
            desc.includes('watchguard') ||
            desc.includes('firebox') ||
            desc.includes('fireware');

        // Exclude other firewall vendors
        const explicitExclusions = [
            'palo alto', 'fortinet', 'fortigate', 'checkpoint', 'sophos',
            'cisco asa', 'juniper', 'sonicwall', 'pfsense', 'opnsense'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasWatchGuardCPE || descHasWatchGuardContext) && !hasExcludedProduct;
    },

    // Zoom: Must be for Zoom video conferencing, not generic "zoom" mentions
    'zoom': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasZoomProduct = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':zoom:') &&
            (p.cpe?.includes(':zoom_') || p.cpe?.includes(':meetings') ||
             p.cpe?.includes(':workplace') || p.cpe?.includes(':rooms') ||
             p.cpe?.includes(':zoom:zoom:'))
        );
        const descHasZoomContext = desc.includes('zoom video') ||
            desc.includes('zoom communications') ||
            desc.includes('zoom client') ||
            desc.includes('zoom meeting') ||
            desc.includes('zoom workplace') ||
            desc.includes('zoom rooms') ||
            (desc.includes('zoom') && (desc.includes('video conferencing') || desc.includes('webinar')));
        return hasZoomProduct || descHasZoomContext;
    },

    // Tripplite UPS: Must be specifically for Tripp Lite UPS/power products
    'tripplite-ups': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasTrippliteProduct = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':tripp_lite:') ||
            p.cpe?.includes(':tripplite:') ||
            p.cpe?.includes(':tripp-lite:')
        );
        // Must mention Tripp Lite specifically in description
        const descHasTrippliteContext = desc.includes('tripp lite') ||
            desc.includes('tripplite') ||
            desc.includes('tripp-lite') ||
            (desc.includes('tripp') && (desc.includes('ups') || desc.includes('power') || desc.includes('pdu')));
        // Exclude common false positives - generic "ups" or "power" mentions without Tripp Lite
        const isGenericPower = (desc.includes('ups') || desc.includes('power')) &&
            !desc.includes('tripp') && !hasTrippliteProduct;
        return (hasTrippliteProduct || descHasTrippliteContext) && !isGenericPower;
    },

    // Crestron Electronics: Must be specifically for Crestron AV/control products
    'crestron': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        // Must have Crestron CPE
        const hasCrestronCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':crestron:')
        );

        // Or description must explicitly mention Crestron
        const descHasCrestronContext = desc.includes('crestron');

        // Explicit exclusions for unrelated products that might appear in keyword searches
        const explicitExclusions = [
            'gogs', 'gitea', 'gitlab', 'github', 'git server',
            'forgejo', 'sourcehut', 'bitbucket'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        // Accept if has Crestron CPE or description mentions Crestron AND doesn't have excluded terms
        return hasCrestronCPE || (descHasCrestronContext && !hasExcludedProduct);
    },

    // Oracle Database: Must be specifically for Oracle database products, not other DBs
    'oracle-database': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        // Must have Oracle CPE for database
        const hasOracleCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':oracle:database') ||
            (p.cpe?.includes(':oracle:') && !p.cpe?.includes(':oracle:mysql'))
        );

        // Description must mention Oracle Database specifically
        const descHasOracleContext =
            desc.includes('oracle database') ||
            desc.includes('oracle db') ||
            desc.includes('oracle oda') ||
            desc.includes('oracle appliance') ||
            (desc.includes('oracle') && (desc.includes('database') || desc.includes('rdbms')));

        // Exclude other database products
        const explicitExclusions = [
            'mongodb', 'mysql', 'postgresql', 'sql server', 'mariadb',
            'redis', 'cassandra', 'elasticsearch', 'dynamodb', 'couchdb',
            'oracle java', 'oracle virtualbox', 'oracle linux'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasOracleCPE || descHasOracleContext) && !hasExcludedProduct;
    },

    // SolarWinds: Must be for SolarWinds, not npm (Node Package Manager)
    'solarwinds': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        // Must have SolarWinds CPE
        const hasSolarWindsCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':solarwinds:')
        );

        // Description must mention SolarWinds specifically
        const descHasSolarWindsContext =
            desc.includes('solarwinds') ||
            desc.includes('orion platform') ||
            (desc.includes('npm') && desc.includes('solarwinds'));

        // Exclude Node.js/npm ecosystem
        const explicitExclusions = [
            'node.js', 'nodejs', 'node package', 'npm registry', 'npm install',
            'package.json', 'javascript', 'npm audit', 'npmjs.org'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        // If description mentions 'npm' but not 'solarwinds', reject it
        const isNodeNPM = desc.includes('npm') && !desc.includes('solarwinds');

        return (hasSolarWindsCPE || descHasSolarWindsContext) && !hasExcludedProduct && !isNodeNPM;
    },

    // ConnectWise: Must be for ConnectWise products
    'connectwise': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasConnectWiseCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':connectwise:')
        );

        const descHasConnectWiseContext =
            desc.includes('connectwise') ||
            desc.includes('screenconnect') ||
            desc.includes('connectwise automate') ||
            desc.includes('connectwise manage');

        // Exclude generic automation/management tools
        const explicitExclusions = [
            'ansible', 'puppet', 'chef', 'terraform', 'jenkins',
            'github actions', 'gitlab ci', 'azure devops'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasConnectWiseCPE || descHasConnectWiseContext) && !hasExcludedProduct;
    },

    // Veeam: Must be for Veeam backup products
    'veeam': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasVeeamCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':veeam:')
        );

        const descHasVeeamContext =
            desc.includes('veeam') ||
            desc.includes('veeam backup') ||
            desc.includes('veeam one');

        // Exclude other backup products
        const explicitExclusions = [
            'acronis', 'commvault', 'veritas', 'rubrik', 'cohesity',
            'dell emc', 'netbackup'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasVeeamCPE || descHasVeeamContext) && !hasExcludedProduct;
    },

    // Zerto: Must be for Zerto disaster recovery products
    'zerto': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasZertoCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':zerto:')
        );

        const descHasZertoContext =
            desc.includes('zerto') ||
            desc.includes('zerto virtual replication');

        // Exclude generic DR terms without Zerto context
        const explicitExclusions = [
            'veeam', 'acronis', 'commvault', 'vmware srm', 'aws disaster',
            'azure site recovery'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasZertoCPE || descHasZertoContext) && !hasExcludedProduct;
    },

    // Bitdefender: Must be for Bitdefender security products
    'bitdefender': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasBitdefenderCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':bitdefender:')
        );

        const descHasBitdefenderContext =
            desc.includes('bitdefender') ||
            desc.includes('gravityzone');

        // Exclude other security vendors
        const explicitExclusions = [
            'norton', 'mcafee', 'kaspersky', 'avast', 'avg',
            'eset', 'trend micro', 'sophos', 'crowdstrike', 'sentinelone'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasBitdefenderCPE || descHasBitdefenderContext) && !hasExcludedProduct;
    },

    // Google Chrome: Must be for Chrome browser, not generic chromium/browser mentions
    'google-chrome': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasChromeCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':google:chrome')
        );

        const descHasChromeContext =
            desc.includes('google chrome') ||
            desc.includes('chrome browser') ||
            (desc.includes('chrome') && desc.includes('google'));

        // Exclude Electron apps and other browsers
        const explicitExclusions = [
            'electron', 'chromium embedded', 'cef', 'edge', 'brave',
            'vivaldi', 'opera'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasChromeCPE || descHasChromeContext) && !hasExcludedProduct;
    },

    // Firefox: Must be for Mozilla Firefox, not generic browser mentions
    'firefox': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasFirefoxCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':mozilla:firefox')
        );

        const descHasFirefoxContext =
            desc.includes('mozilla firefox') ||
            desc.includes('firefox browser') ||
            (desc.includes('firefox') && desc.includes('mozilla'));

        // Exclude other browsers
        const explicitExclusions = [
            'chrome', 'edge', 'safari', 'opera', 'brave', 'vivaldi'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasFirefoxCPE || descHasFirefoxContext) && !hasExcludedProduct;
    }
};

/**
 * Validate vulnerability against product-specific rules
 */
const validateVulnerabilityForAsset = (vuln, assetId) => {
    const validator = PRODUCT_VALIDATORS[assetId];
    if (!validator) {
        return true; // No specific validator, accept all
    }
    return validator(vuln);
};

/**
 * Known trusted domains for vulnerability references
 * NOTE: Removed securityfocus.com and securitytracker.com as they are no longer active (21JAN2026)
 */
const TRUSTED_REFERENCE_DOMAINS = [
    'nvd.nist.gov',
    'cve.org',
    'cve.mitre.org',
    'github.com',
    'security.gentoo.org',
    'access.redhat.com',
    'ubuntu.com',
    'debian.org',
    'oracle.com',
    'microsoft.com',
    'cisco.com',
    'support.apple.com',
    'kb.cert.org',
    // 'securityfocus.com', // REMOVED - Site no longer active
    'exploit-db.com',
    'packetstormsecurity.com',
    'zerodayinitiative.com',
    // 'securitytracker.com', // REMOVED - Site no longer active (leads to blank landing page)
    'openwall.com',
    'seclists.org',
    'bugzilla',
    'hackerone.com',
    'veeam.com',
    'mozilla.org',
    'chromium.org',
    'google.com',
    'adobe.com',
    'vmware.com',
    'fortinet.com',
    'paloaltonetworks.com',
    'tenable.com',
    'rapid7.com',
    'qualys.com',
    'sec.cloudapps.cisco.com',
    'tools.cisco.com'
];

/**
 * Known dead/defunct domains that should always be filtered out
 * These sites no longer operate or lead to non-functional pages
 */
const DEAD_REFERENCE_DOMAINS = [
    'securityfocus.com',
    'securitytracker.com'
];

/**
 * Validate and filter reference URLs
 * Removes broken, malformed, dead, or untrusted reference links
 */
const validateReferences = (references) => {
    if (!references || !Array.isArray(references)) {
        return [];
    }

    return references.filter(ref => {
        if (!ref.url) return false;

        try {
            const url = new URL(ref.url);

            // Must be http or https
            if (!['http:', 'https:'].includes(url.protocol)) {
                return false;
            }

            const hostname = url.hostname.toLowerCase();

            // Filter out known dead/defunct domains
            const isDead = DEAD_REFERENCE_DOMAINS.some(domain =>
                hostname === domain || hostname.endsWith('.' + domain)
            );
            if (isDead) {
                console.log(`[NVD API] Filtering out dead domain: ${hostname}`);
                return false;
            }

            // Check if domain is trusted or contains trusted domain
            const isTrusted = TRUSTED_REFERENCE_DOMAINS.some(domain =>
                hostname === domain || hostname.endsWith('.' + domain)
            );

            // Also allow if it has useful tags from NVD
            const hasUsefulTags = ref.tags?.some(tag =>
                ['Vendor Advisory', 'Patch', 'Exploit', 'Third Party Advisory', 'Mitigation'].includes(tag)
            );

            return isTrusted || hasUsefulTags;
        } catch {
            // Invalid URL
            return false;
        }
    });
};

/**
 * Calculate appropriate resultsPerPage based on date range
 * Longer time ranges need more results to avoid missing vulnerabilities
 * NVD API has a 120-day max limit on date ranges
 */
const getResultsPerPageForRange = (startDate, endDate) => {
    const daysDiff = Math.ceil((endDate - startDate) / (1000 * 60 * 60 * 24));

    if (daysDiff <= 7) return 100;
    if (daysDiff <= 30) return 200;
    if (daysDiff <= 90) return 500;
    return 1000; // For 90-120 day ranges
};

/**
 * Fetch vulnerabilities for a specific asset
 * Searches both by publication date AND last modified date to catch updated CVEs
 * Supports new cpeProducts array format
 * @param {Object} asset - Asset object with keywords and cpe info
 * @param {Date} startDate - Start of date range
 * @param {Date} endDate - End of date range
 * @returns {Promise<Array>} Array of vulnerabilities for the asset
 */
export const fetchVulnerabilitiesForAsset = async (asset, startDate, endDate) => {
    const results = [];
    const resultsPerPage = getResultsPerPageForRange(startDate, endDate);

    // Some assets prefer keyword search only (e.g., Veeam where CPE matching is unreliable)
    if (asset.preferKeywordSearch && asset.keywords?.length > 0) {
        const primaryKeyword = asset.keywords[0];

        const keywordResults = await searchNVDByKeyword(
            primaryKeyword,
            startDate,
            endDate,
            resultsPerPage
        );
        results.push(...keywordResults);
    }
    // For most assets: search BOTH by CPE AND by keywords to ensure complete coverage
    // CPE search is accurate but misses newly published CVEs that don't have CPE data yet
    // Keyword search catches those CVEs but may have more false positives (filtered later)
    else {
        // CPE-based search (accurate for CVEs with CPE data)
        if (asset.cpeVendor) {
            const cpeProducts = asset.cpeProducts || (asset.cpeProduct ? [asset.cpeProduct] : []);
            const cpeVendors = [asset.cpeVendor, ...(asset.additionalCpeVendors || [])];

            for (const vendor of cpeVendors) {
                for (const product of cpeProducts) {
                    const cpeResults = await searchNVDByCPE(
                        vendor,
                        product,
                        startDate,
                        endDate,
                        resultsPerPage
                    );
                    results.push(...cpeResults);
                }
            }
        }

        // ALSO search by keywords to catch CVEs without CPE data yet
        // NVD often publishes CVEs before adding CPE entries, especially for new vulns
        if (asset.keywords?.length > 0) {
            const primaryKeyword = asset.keywords[0];

            const keywordResults = await searchNVDByKeyword(
                primaryKeyword,
                startDate,
                endDate,
                resultsPerPage
            );
            results.push(...keywordResults);
        }
    }

    // Deduplicate results (same CVE might appear in both published and modified searches)
    const uniqueResults = deduplicateVulnerabilities(results);

    // Validate dates - filter out CVEs that don't fall within the requested time range
    // This prevents old CVEs from appearing when they shouldn't
    const dateValidatedResults = uniqueResults.filter(vuln => {
        const isValid = isWithinDateRange(vuln, startDate, endDate);
        if (!isValid) {
            console.log(`[NVD API] Filtering out ${vuln.id} - dates outside range (pub: ${vuln.published}, mod: ${vuln.lastModified})`);
        }
        return isValid;
    });

    // Apply product-specific validation to filter out false positives
    const validatedResults = dateValidatedResults.filter(vuln =>
        validateVulnerabilityForAsset(vuln, asset.id)
    );

    // Validate and filter references to remove broken/dead links
    const resultsWithValidRefs = validatedResults.map(vuln => ({
        ...vuln,
        references: validateReferences(vuln.references)
    }));

    // Sort by most recent date (either published or lastModified) - most recent first
    const sortedResults = sortByMostRecentDate(resultsWithValidRefs);

    // Add asset ID to each result
    return sortedResults.map(vuln => ({
        ...vuln,
        assetId: asset.id,
        assetName: asset.name
    }));
};

export { sortByMostRecentDate, getMostRecentDate };

export default {
    searchNVDByKeyword,
    searchNVDByKeywordLastModified,
    searchNVDByCPE,
    searchNVDByCPELastModified,
    fetchVulnerabilitiesForAsset,
    sortByMostRecentDate,
    getMostRecentDate
};
