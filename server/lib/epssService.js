// EPSS (Exploit Prediction Scoring System) Service
// Fetches exploit probability scores from FIRST.org API
// https://www.first.org/epss/api

const EPSS_API_BASE = 'https://api.first.org/data/v1/epss';
const BATCH_SIZE = 100; // Max CVEs per request

/**
 * Fetch EPSS scores for a batch of CVE IDs
 * @param {string[]} cveIds - Array of CVE IDs
 * @returns {Promise<Map<string, {score: number, percentile: number}>>}
 */
export async function fetchEPSSScores(cveIds) {
    if (!cveIds || cveIds.length === 0) return new Map();

    const results = new Map();

    // Process in batches of 100
    for (let i = 0; i < cveIds.length; i += BATCH_SIZE) {
        const batch = cveIds.slice(i, i + BATCH_SIZE);
        const cveParam = batch.join(',');

        try {
            const response = await fetch(`${EPSS_API_BASE}?cve=${cveParam}`);
            if (!response.ok) {
                console.warn(`[EPSS] API error: ${response.status}`);
                continue;
            }

            const data = await response.json();

            if (data.data && Array.isArray(data.data)) {
                data.data.forEach(entry => {
                    results.set(entry.cve, {
                        score: parseFloat(entry.epss),
                        percentile: parseFloat(entry.percentile)
                    });
                });
            }

            console.log(`[EPSS] Fetched scores for ${data.data?.length || 0}/${batch.length} CVEs`);
        } catch (error) {
            console.error(`[EPSS] Fetch failed for batch starting at ${i}:`, error.message);
        }
    }

    return results;
}

/**
 * Enrich vulnerability objects with EPSS data
 * @param {Array} vulns - Array of vulnerability objects
 * @returns {Promise<Array>} Enriched vulnerability objects
 */
export async function enrichWithEPSS(vulns) {
    if (!vulns || vulns.length === 0) return vulns;

    // Collect all CVE IDs
    const cveIds = vulns
        .map(v => v.id)
        .filter(id => id && id.startsWith('CVE-'));

    if (cveIds.length === 0) return vulns;

    const epssScores = await fetchEPSSScores(cveIds);

    // Merge EPSS data into vulnerability objects
    return vulns.map(vuln => {
        const epss = epssScores.get(vuln.id);
        if (epss) {
            return {
                ...vuln,
                epssScore: epss.score,
                epssPercentile: epss.percentile
            };
        }
        return vuln;
    });
}
