// NVD API Service for Vercel Serverless Functions
// Fetches vulnerability data from NVD and CISA APIs

import { ASSETS } from './assets.js';
import { enrichWithEPSS } from './epssService.js';
import { enrichWithAttackTechniques } from './attackMapping.js';
import { enrichWithThreatActors } from './threatActorService.js';

// API Configuration
const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
// NVD API Key - MUST be set via environment variable (never hardcode!)
// Get your API key from: https://nvd.nist.gov/developers/request-an-api-key
const NVD_API_KEY = process.env.NVD_API_KEY;

if (!NVD_API_KEY) {
    console.warn('WARNING: NVD_API_KEY not set! Rate limit will be severely restricted (5 requests/30 seconds vs 50)');
}

// Rate limiting configuration:
// - WITH API key: 50 requests per 30 seconds = 600ms minimum delay (using 800ms to be safe)
// - WITHOUT API key: 5 requests per 30 seconds = 6000ms minimum delay (using 6500ms to be safe)
const REQUEST_DELAY_WITH_KEY = 800;    // 0.8 seconds with API key
const REQUEST_DELAY_NO_KEY = 6500;     // 6.5 seconds without API key
const MAX_RETRY_DELAY = 60000;         // Max 60 seconds between retries

let lastRequestTime = 0;
let consecutiveErrors = 0;

// Get dynamic delay based on API key presence and error state
const getRequestDelay = () => {
    const baseDelay = NVD_API_KEY ? REQUEST_DELAY_WITH_KEY : REQUEST_DELAY_NO_KEY;
    if (consecutiveErrors > 0) {
        const backoffDelay = Math.min(baseDelay * Math.pow(2, consecutiveErrors), MAX_RETRY_DELAY);
        console.log(`[NVD] Using backoff delay: ${backoffDelay}ms (${consecutiveErrors} consecutive errors)`);
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
        console.log(`[NVD] Rate limiting: waiting ${waitTime}ms`);
        await wait(waitTime);
    }
    lastRequestTime = Date.now();
};

const recordSuccess = () => {
    if (consecutiveErrors > 0) {
        console.log(`[NVD] Request successful, resetting error counter`);
        consecutiveErrors = 0;
    }
};

const recordError = () => {
    consecutiveErrors++;
    console.warn(`[NVD] Request failed, consecutive errors: ${consecutiveErrors}`);
};

/**
 * Calculate date range based on time period
 */
const getDateRange = (timeRange) => {
    const endDate = new Date();
    let startDate = new Date();

    switch (timeRange) {
        case '24h': startDate.setHours(startDate.getHours() - 24); break;
        case '7d': startDate.setDate(startDate.getDate() - 7); break;
        case '30d': startDate.setDate(startDate.getDate() - 30); break;
        case '90d': startDate.setDate(startDate.getDate() - 90); break;
        case '119d': startDate.setDate(startDate.getDate() - 119); break;
        default: startDate.setDate(startDate.getDate() - 7);
    }

    return { startDate, endDate };
};

/**
 * Fetch from NVD API with rate limiting and retry logic
 */
async function fetchNVD(params) {
    await enforceRateLimit();

    const url = `${NVD_API_BASE}?${params.toString()}`;

    const headers = {};
    if (NVD_API_KEY) {
        headers['apiKey'] = NVD_API_KEY;
    }

    try {
        const response = await fetch(url, { headers });

        if (!response.ok) {
            // Handle rate limiting specifically
            if (response.status === 429 || response.status === 403) {
                recordError();
                console.warn(`[NVD] Rate limited (${response.status}), retrying with longer delay...`);
                await wait(getRequestDelay());
                const retryResponse = await fetch(url, { headers });
                if (retryResponse.ok) {
                    recordSuccess();
                    return retryResponse.json();
                }
            }
            throw new Error(`NVD API error: ${response.status}`);
        }

        recordSuccess();
        return response.json();
    } catch (error) {
        recordError();
        throw error;
    }
}

/**
 * Search NVD by CPE
 */
async function searchNVDByCPE(vendor, product, startDate, endDate, resultsPerPage = 100) {
    const cpeMatch = `cpe:2.3:*:${vendor}:${product}:*:*:*:*:*:*:*:*`;

    const params = new URLSearchParams({
        virtualMatchString: cpeMatch,
        resultsPerPage: resultsPerPage.toString(),
        pubStartDate: startDate.toISOString(),
        pubEndDate: endDate.toISOString()
    });

    try {
        console.log(`[NVD] CPE search: ${vendor}:${product}`);
        const data = await fetchNVD(params);
        console.log(`[NVD] ${vendor}:${product} returned ${data.totalResults || 0} results`);
        return parseCVEResponse(data);
    } catch (error) {
        console.error(`NVD CPE search failed for ${vendor}:${product}:`, error.message);
        return [];
    }
}

/**
 * Search NVD by keyword
 */
async function searchNVDByKeyword(keyword, startDate, endDate, resultsPerPage = 100) {
    const params = new URLSearchParams({
        keywordSearch: keyword,
        resultsPerPage: resultsPerPage.toString(),
        pubStartDate: startDate.toISOString(),
        pubEndDate: endDate.toISOString()
    });

    try {
        const data = await fetchNVD(params);
        return parseCVEResponse(data);
    } catch (error) {
        console.error(`NVD keyword search failed for "${keyword}":`, error.message);
        return [];
    }
}

/**
 * Parse NVD API response
 */
function parseCVEResponse(data) {
    if (!data.vulnerabilities || !Array.isArray(data.vulnerabilities)) {
        return [];
    }

    return data.vulnerabilities.map(vuln => {
        const cve = vuln.cve;

        // Get CVSS score
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

        const description = cve.descriptions?.find(d => d.lang === 'en')?.value ||
            cve.descriptions?.[0]?.value || 'No description available';

        const references = cve.references?.map(ref => ({
            url: ref.url,
            source: ref.source,
            tags: ref.tags || []
        })) || [];

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
}

function getSeverityFromScore(score) {
    if (score === null || score === undefined) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score >= 0.1) return 'LOW';
    return 'NONE';
}

function getSeverityFromScoreV2(score) {
    if (score === null || score === undefined) return 'UNKNOWN';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}

/**
 * Get the most recent date between published and lastModified for sorting
 */
function getMostRecentDate(vuln) {
    const published = vuln.published ? new Date(vuln.published).getTime() : 0;
    const lastModified = vuln.lastModified ? new Date(vuln.lastModified).getTime() : 0;
    return Math.max(published, lastModified);
}

/**
 * Sort vulnerabilities by most recent date (either published or lastModified)
 */
function sortByMostRecentDate(vulnerabilities) {
    return [...vulnerabilities].sort((a, b) => getMostRecentDate(b) - getMostRecentDate(a));
}

/**
 * Validate that a vulnerability's published date falls within the requested time range
 * NOTE: Only checking published date - NVD's lastModified reflects when NVD touched the
 * record (even for minor metadata changes), not when the vulnerability was meaningfully
 * updated. Using lastModified caused old CVEs to appear with misleading dates.
 */
function isWithinDateRange(vuln, startDate, endDate) {
    const startTime = startDate.getTime();
    const endTime = endDate.getTime();
    const published = vuln.published ? new Date(vuln.published).getTime() : 0;
    return published >= startTime && published <= endTime;
}

/**
 * Known dead/defunct domains that should be filtered out
 */
const DEAD_REFERENCE_DOMAINS = ['securityfocus.com', 'securitytracker.com'];

/**
 * Filter out references from dead domains
 */
function filterDeadReferences(references) {
    if (!references || !Array.isArray(references)) return [];
    return references.filter(ref => {
        if (!ref.url) return false;
        try {
            const url = new URL(ref.url);
            const hostname = url.hostname.toLowerCase();
            const isDead = DEAD_REFERENCE_DOMAINS.some(domain =>
                hostname === domain || hostname.endsWith('.' + domain)
            );
            return !isDead;
        } catch {
            return false;
        }
    });
}

/**
 * Fetch CISA KEV catalog
 */
let cisaCache = null;
let cisaCacheTime = 0;

async function fetchCISAKEV() {
    // Cache CISA data for 1 hour
    if (cisaCache && (Date.now() - cisaCacheTime) < 3600000) {
        return cisaCache;
    }

    try {
        const response = await fetch(CISA_KEV_URL);
        if (!response.ok) throw new Error(`CISA API error: ${response.status}`);
        const data = await response.json();
        cisaCache = data.vulnerabilities || [];
        cisaCacheTime = Date.now();
        console.log(`Fetched ${cisaCache.length} CISA KEV entries`);
        return cisaCache;
    } catch (error) {
        console.error('CISA fetch failed:', error.message);
        return cisaCache || [];
    }
}

/**
 * Search CISA KEV for asset
 */
async function searchCISAForAsset(asset, startDate, endDate) {
    const allVulns = await fetchCISAKEV();
    if (!allVulns.length) return [];

    const searchTerms = [
        asset.vendor?.toLowerCase(),
        asset.name?.toLowerCase(),
        ...(asset.keywords || []).map(k => k.toLowerCase())
    ].filter(Boolean);

    const matches = allVulns.filter(vuln => {
        const dateAdded = new Date(vuln.dateAdded);
        if (dateAdded < startDate || dateAdded > endDate) return false;

        const vulnVendor = vuln.vendorProject?.toLowerCase() || '';
        const vulnProduct = vuln.product?.toLowerCase() || '';
        const vulnName = vuln.vulnerabilityName?.toLowerCase() || '';

        return searchTerms.some(term =>
            vulnVendor.includes(term) || vulnProduct.includes(term) || vulnName.includes(term)
        );
    });

    return matches.map(vuln => ({
        id: vuln.cveID,
        published: vuln.dateAdded,
        lastModified: vuln.dateAdded,
        description: vuln.shortDescription || vuln.vulnerabilityName,
        cvssScore: null,
        severity: 'HIGH',
        cvssVector: null,
        references: [
            { url: `https://nvd.nist.gov/vuln/detail/${vuln.cveID}`, source: 'NVD', tags: ['Reference'] }
        ],
        affectedProducts: [{ vendor: vuln.vendorProject, product: vuln.product }],
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
        activelyExploited: true
    }));
}

/**
 * Product validators to filter false positives
 * These validators must stay in sync with the frontend validators in src/services/nvdApi.js
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
        // NOTE: 'linux', 'macos', 'apple' intentionally NOT excluded — many Microsoft
        // products are cross-platform (Edge, .NET, VS Code, SQL Server Linux edition)
        const otherVendorExclusions = [
            'libreoffice', 'openoffice', 'google docs', 'google workspace'
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
        const descHasTrippliteContext = desc.includes('tripp lite') ||
            desc.includes('tripplite') ||
            desc.includes('tripp-lite') ||
            (desc.includes('tripp') && (desc.includes('ups') || desc.includes('power') || desc.includes('pdu')));
        const isGenericPower = (desc.includes('ups') || desc.includes('power')) &&
            !desc.includes('tripp') && !hasTrippliteProduct;
        return (hasTrippliteProduct || descHasTrippliteContext) && !isGenericPower;
    },

    // Crestron Electronics: Must be specifically for Crestron AV/control products
    'crestron': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasCrestronCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':crestron:')
        );

        const descHasCrestronContext = desc.includes('crestron');

        const explicitExclusions = [
            'gogs', 'gitea', 'gitlab', 'github', 'git server',
            'forgejo', 'sourcehut', 'bitbucket'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return hasCrestronCPE || (descHasCrestronContext && !hasExcludedProduct);
    },

    // Oracle Database: Must be specifically for Oracle database products, not other DBs
    'oracle-database': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';

        const hasOracleCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':oracle:database') ||
            (p.cpe?.includes(':oracle:') && !p.cpe?.includes(':oracle:mysql'))
        );

        const descHasOracleContext =
            desc.includes('oracle database') ||
            desc.includes('oracle db') ||
            desc.includes('oracle oda') ||
            desc.includes('oracle appliance') ||
            (desc.includes('oracle') && (desc.includes('database') || desc.includes('rdbms')));

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

        const hasSolarWindsCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':solarwinds:')
        );

        const descHasSolarWindsContext =
            desc.includes('solarwinds') ||
            desc.includes('orion platform') ||
            (desc.includes('npm') && desc.includes('solarwinds'));

        const explicitExclusions = [
            'node.js', 'nodejs', 'node package', 'npm registry', 'npm install',
            'package.json', 'javascript', 'npm audit', 'npmjs.org'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

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

        const explicitExclusions = [
            'chrome', 'edge', 'safari', 'opera', 'brave', 'vivaldi'
        ];
        const hasExcludedProduct = explicitExclusions.some(term => desc.includes(term));

        return (hasFirefoxCPE || descHasFirefoxContext) && !hasExcludedProduct;
    },

    // Ubuntu: Must be for Canonical Ubuntu Linux
    'ubuntu': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasUbuntuCPE = vuln.affectedProducts?.some(p => p.cpe?.includes(':canonical:'));
        const descHasContext = desc.includes('ubuntu');
        const exclusions = ['mint', 'kubuntu', 'lubuntu'];
        const hasExcluded = exclusions.some(t => desc.includes(t) && !desc.includes('ubuntu'));
        return (hasUbuntuCPE || descHasContext) && !hasExcluded;
    },

    // RHEL: Must be for Red Hat Enterprise Linux
    'rhel': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasRHELCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':redhat:enterprise_linux')
        );
        const descHasContext = desc.includes('red hat enterprise linux') || desc.includes('rhel');
        const exclusions = ['fedora', 'centos stream'];
        const hasExcluded = exclusions.some(t => desc.includes(t)) && !descHasContext && !hasRHELCPE;
        return (hasRHELCPE || descHasContext) && !hasExcluded;
    },

    // Debian: Must be for Debian Linux
    'debian': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasDebianCPE = vuln.affectedProducts?.some(p => p.cpe?.includes(':debian:'));
        const descHasContext = desc.includes('debian');
        return hasDebianCPE || descHasContext;
    },

    // AWS: Must be for Amazon Web Services products
    'aws': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasAWSCPE = vuln.affectedProducts?.some(p => p.cpe?.includes(':amazon:'));
        const descHasContext = desc.includes('amazon web services') || desc.includes('aws') ||
            desc.includes('amazon linux') || desc.includes('amazon ec2') || desc.includes('amazon s3');
        const exclusions = ['amazon kindle', 'amazon fire', 'amazon alexa', 'amazon ring'];
        const hasExcluded = exclusions.some(t => desc.includes(t));
        return (hasAWSCPE || descHasContext) && !hasExcluded;
    },

    // Azure Cloud: Must be for Azure cloud services (not general Microsoft)
    'azure-cloud': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasAzureCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':microsoft:azure')
        );
        const descHasContext = desc.includes('azure') && (
            desc.includes('microsoft') || desc.includes('cloud') ||
            desc.includes('active directory') || desc.includes('devops')
        );
        return hasAzureCPE || descHasContext;
    },

    // Google Cloud: Must be for GCP, not Chrome/Android
    'google-cloud': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasGCPCPE = vuln.affectedProducts?.some(p =>
            p.cpe?.includes(':google:cloud_platform') || p.cpe?.includes(':google:cloud_sdk')
        );
        const descHasContext = desc.includes('google cloud') || desc.includes('gcp') ||
            desc.includes('cloud sdk');
        const exclusions = ['chrome', 'android', 'pixel', 'chromium'];
        const hasExcluded = exclusions.some(t => desc.includes(t)) && !descHasContext;
        return hasGCPCPE || descHasContext;
    },

    // Fortinet: Must be for Fortinet products
    'fortinet': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasFortinetCPE = vuln.affectedProducts?.some(p => p.cpe?.includes(':fortinet:'));
        const descHasContext = desc.includes('fortinet') || desc.includes('fortigate') ||
            desc.includes('fortios') || desc.includes('fortimanager') || desc.includes('fortianalyzer');
        const exclusions = ['watchguard', 'palo alto', 'checkpoint', 'cisco asa'];
        const hasExcluded = exclusions.some(t => desc.includes(t));
        return (hasFortinetCPE || descHasContext) && !hasExcluded;
    },

    // Palo Alto Networks: Must be for PAN products
    'paloalto': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasPANCPE = vuln.affectedProducts?.some(p => p.cpe?.includes(':paloaltonetworks:'));
        const descHasContext = desc.includes('palo alto') || desc.includes('pan-os') ||
            desc.includes('cortex xdr') || desc.includes('globalprotect') || desc.includes('panorama');
        const exclusions = ['fortinet', 'watchguard', 'checkpoint', 'cisco asa'];
        const hasExcluded = exclusions.some(t => desc.includes(t));
        return (hasPANCPE || descHasContext) && !hasExcluded;
    },

    // Juniper: Must be for Juniper Networks products
    'juniper': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasJuniperCPE = vuln.affectedProducts?.some(p => p.cpe?.includes(':juniper:'));
        const descHasContext = desc.includes('juniper') || desc.includes('junos');
        const exclusions = ['cisco', 'fortinet', 'palo alto', 'arista'];
        const hasExcluded = exclusions.some(t => desc.includes(t));
        return (hasJuniperCPE || descHasContext) && !hasExcluded;
    },

    // Docker: Must be for Docker container products
    'docker': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasDockerCPE = vuln.affectedProducts?.some(p => p.cpe?.includes(':docker:'));
        const descHasContext = desc.includes('docker engine') || desc.includes('docker desktop') ||
            (desc.includes('docker') && (desc.includes('container') || desc.includes('daemon') || desc.includes('moby')));
        const exclusions = ['podman', 'containerd', 'cri-o'];
        const hasExcluded = exclusions.some(t => desc.includes(t)) && !hasDockerCPE;
        return hasDockerCPE || descHasContext;
    },

    // Kubernetes: Must be for Kubernetes orchestration
    'kubernetes': (vuln) => {
        const desc = vuln.description?.toLowerCase() || '';
        const hasK8sCPE = vuln.affectedProducts?.some(p => p.cpe?.includes(':kubernetes:'));
        const descHasContext = desc.includes('kubernetes') || desc.includes('k8s');
        const exclusions = ['openshift', 'rancher', 'docker swarm'];
        const hasExcluded = exclusions.some(t => desc.includes(t)) && !descHasContext && !hasK8sCPE;
        return (hasK8sCPE || descHasContext) && !hasExcluded;
    }
};

function validateVulnerabilityForAsset(vuln, assetId) {
    const validator = PRODUCT_VALIDATORS[assetId];
    return validator ? validator(vuln) : true;
}

/**
 * Search NVD by keyword with lastModified date range
 */
async function searchNVDByKeywordLastModified(keyword, startDate, endDate, resultsPerPage = 100) {
    const params = new URLSearchParams({
        keywordSearch: keyword,
        resultsPerPage: resultsPerPage.toString(),
        lastModStartDate: startDate.toISOString(),
        lastModEndDate: endDate.toISOString()
    });

    try {
        const data = await fetchNVD(params);
        const results = parseCVEResponse(data);
        return results.map(r => ({ ...r, recentlyModified: true }));
    } catch (error) {
        console.error(`NVD keyword lastMod search failed for "${keyword}":`, error.message);
        return [];
    }
}

/**
 * Search NVD by CPE with lastModified date range
 */
async function searchNVDByCPELastModified(vendor, product, startDate, endDate, resultsPerPage = 100) {
    const cpeMatch = `cpe:2.3:*:${vendor}:${product}:*:*:*:*:*:*:*:*`;

    const params = new URLSearchParams({
        virtualMatchString: cpeMatch,
        resultsPerPage: resultsPerPage.toString(),
        lastModStartDate: startDate.toISOString(),
        lastModEndDate: endDate.toISOString()
    });

    try {
        console.log(`[NVD] CPE lastMod search: ${vendor}:${product}`);
        const data = await fetchNVD(params);
        console.log(`[NVD] ${vendor}:${product} (lastMod) returned ${data.totalResults || 0} results`);
        const results = parseCVEResponse(data);
        return results.map(r => ({ ...r, recentlyModified: true }));
    } catch (error) {
        console.error(`NVD CPE lastMod search failed for ${vendor}:${product}:`, error.message);
        return [];
    }
}

/**
 * Fetch vulnerabilities for a single asset
 * Uses keyword-primary search strategy: a single broad keyword search per asset
 * instead of per-CPE-product searches (which caused too many API calls and timeouts).
 * Validators handle false positive filtering.
 */
async function fetchVulnerabilitiesForAsset(asset, startDate, endDate) {
    const results = [];

    // Keyword-primary search: one broad keyword search per asset
    // keywords[0] should be the shortest unambiguous vendor/product term
    // NVD keyword search requires ALL words to match, so shorter = broader coverage
    if (asset.keywords?.length > 0) {
        const keyword = asset.keywords[0];
        console.log(`[NVD] Keyword search for ${asset.name}: "${keyword}"`);
        const keywordResults = await searchNVDByKeyword(keyword, startDate, endDate, 2000);
        results.push(...keywordResults);
    }

    // Vendor-level CPE fallback: catches CVEs where the description doesn't mention
    // the vendor name at all (e.g., some Veeam CVEs just say "A vulnerability that enables..."
    // without saying "Veeam"). This is a single API call per asset (not per-product).
    if (asset.cpeVendor) {
        console.log(`[NVD] Vendor CPE fallback for ${asset.name}: ${asset.cpeVendor}:*`);
        const cpeResults = await searchNVDByCPE(asset.cpeVendor, '*', startDate, endDate, 2000);
        results.push(...cpeResults);
    }

    // Deduplicate (keep recentlyModified version if available)
    const seen = new Map();
    results.forEach(vuln => {
        const existing = seen.get(vuln.id);
        if (!existing || vuln.recentlyModified) {
            seen.set(vuln.id, vuln);
        }
    });

    // Validate dates - filter out CVEs that don't fall within the requested time range
    const dateValidated = Array.from(seen.values())
        .filter(vuln => {
            const isValid = isWithinDateRange(vuln, startDate, endDate);
            if (!isValid) {
                console.log(`[NVD] Filtering out ${vuln.id} - dates outside range`);
            }
            return isValid;
        });

    // Apply product-specific validation to filter out false positives
    const validated = dateValidated.filter(vuln => validateVulnerabilityForAsset(vuln, asset.id));

    // Filter out dead references and sort by most recent date
    const withValidRefs = validated.map(vuln => ({
        ...vuln,
        references: filterDeadReferences(vuln.references)
    }));

    const sorted = sortByMostRecentDate(withValidRefs);

    return sorted.map(vuln => ({
        ...vuln,
        assetId: asset.id,
        assetName: asset.name
    }));
}

/**
 * Fetch all vulnerabilities for all assets
 */
export async function fetchAllVulnerabilities(timeRange = '7d') {
    console.log(`[Server] Fetching vulnerabilities for ${timeRange}`);
    const { startDate, endDate } = getDateRange(timeRange);

    const vulnerabilities = {};
    const allVulns = [];

    for (let i = 0; i < ASSETS.length; i++) {
        const asset = ASSETS[i];
        console.log(`[${i + 1}/${ASSETS.length}] Fetching: ${asset.name}`);

        try {
            // Fetch from NVD
            const nvdVulns = await fetchVulnerabilitiesForAsset(asset, startDate, endDate);

            // Fetch from CISA
            let cisaVulns = [];
            try {
                cisaVulns = await searchCISAForAsset(asset, startDate, endDate);
            } catch (e) {
                console.warn(`CISA failed for ${asset.name}`);
            }

            // Merge (NVD + CISA)
            const cisaVulnMap = new Map(cisaVulns.map(v => [v.id, v]));
            const merged = nvdVulns.map(vuln => {
                const cisaVuln = cisaVulnMap.get(vuln.id);
                return {
                    ...vuln,
                    activelyExploited: cisaVuln ? true : vuln.activelyExploited,
                    cisaData: cisaVuln?.cisaData || vuln.cisaData
                };
            });

            // Add CISA-only vulnerabilities
            const nvdIds = new Set(nvdVulns.map(v => v.id));
            const cisaOnly = cisaVulns.filter(v => !nvdIds.has(v.id));
            merged.push(...cisaOnly);

            // Sort and enrich per-asset vulnerabilities
            const sortedMerged = sortByMostRecentDate(merged);
            const withAttack = enrichWithAttackTechniques(sortedMerged);
            const withEPSS = await enrichWithEPSS(withAttack);
            const enriched = enrichWithThreatActors(withEPSS);

            vulnerabilities[asset.id] = enriched;
            allVulns.push(...enriched);

            console.log(`  Found ${merged.length} vulnerabilities`);
        } catch (error) {
            console.error(`Error for ${asset.name}:`, error.message);
            vulnerabilities[asset.id] = [];
        }
    }

    return {
        byAsset: vulnerabilities,
        all: sortByMostRecentDate(allVulns), // Sort by max(published, lastModified) - most recent first
        fetchedAt: new Date().toISOString(),
        timeRange,
        source: 'NVD'
    };
}

export {
    fetchVulnerabilitiesForAsset,
    searchCISAForAsset,
    sortByMostRecentDate,
    getDateRange
};

export default { fetchAllVulnerabilities };
