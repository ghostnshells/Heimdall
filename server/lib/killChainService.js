// Kill Chain Composer — synthesizes CVEs into attack chains spanning kill chain stages
// Pure synthesis on existing enriched vulnerability data

import { getVulnData } from './cache.js';
import { cacheGet, cacheSet } from './db.js';

// ── Kill Chain Stage Definitions ────────────────────────────────────

const KILL_CHAIN_STAGES = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Lateral Movement',
    'Collection',
    'Exfiltration',
    'Impact',
];

const STAGE_INDEX = Object.fromEntries(KILL_CHAIN_STAGES.map((s, i) => [s, i]));

// ── Technique → Stage Reverse Index ─────────────────────────────────

const TECHNIQUE_TO_STAGE = {
    T1190: 'Initial Access',
    T1133: 'Initial Access',
    T1566: 'Initial Access',
    T1078: 'Initial Access',
    T1189: 'Initial Access',
    T1059: 'Execution',
    T1203: 'Execution',
    T1505: 'Persistence',
    T1068: 'Privilege Escalation',
    T1211: 'Defense Evasion',
    T1212: 'Credential Access',
    T1210: 'Lateral Movement',
    T1005: 'Collection',
    T1567: 'Exfiltration',
    T1499: 'Impact',
    T1486: 'Impact',
    T1565: 'Impact',
};

const CACHE_TTL = 600; // 10 minutes

// ── Stage Classification ────────────────────────────────────────────

function classifyVuln(vuln) {
    const stages = new Set();
    if (Array.isArray(vuln.attackTechniques)) {
        for (const tech of vuln.attackTechniques) {
            const stage = TECHNIQUE_TO_STAGE[tech.id];
            if (stage) stages.add(stage);
        }
    }
    return Array.from(stages).sort((a, b) => STAGE_INDEX[a] - STAGE_INDEX[b]);
}

// ── Chain Scoring ───────────────────────────────────────────────────

function scoreChain(chain) {
    const stageSpan = chain.stages.length;
    const maxEPSS = Math.max(...chain.steps.map(s => s.epssScore || 0));
    const maxCVSS = Math.max(...chain.steps.map(s => s.cvssScore || 0));

    const assets = new Set(chain.steps.map(s => s.asset));
    const crossAssetBonus = assets.size > 1 ? 1 : 0;

    const kevBonus = chain.steps.some(s => s.activelyExploited) ? 1 : 0;
    const threatActorBonus = chain.steps.some(s =>
        Array.isArray(s.threatActors) && s.threatActors.length > 0
    ) ? 1 : 0;

    return Math.round(
        (stageSpan / 10) * 25 +
        maxEPSS * 25 +
        (maxCVSS / 10) * 20 +
        crossAssetBonus * 15 +
        kevBonus * 10 +
        threatActorBonus * 5
    );
}

// ── Chain Building ──────────────────────────────────────────────────

function buildChains(vulns) {
    // Index vulns by stage
    const vulnsByStage = {};
    for (const stage of KILL_CHAIN_STAGES) {
        vulnsByStage[stage] = [];
    }

    for (const vuln of vulns) {
        const stages = classifyVuln(vuln);
        for (const stage of stages) {
            vulnsByStage[stage].push(vuln);
        }
    }

    // Sort each stage bucket by composite score (EPSS + CVSS) descending
    for (const stage of KILL_CHAIN_STAGES) {
        vulnsByStage[stage].sort((a, b) => {
            const scoreA = (a.epssScore || 0) + (a.cvssScore || 0) / 10;
            const scoreB = (b.epssScore || 0) + (b.cvssScore || 0) / 10;
            return scoreB - scoreA;
        });
    }

    // Entry stages: Initial Access, Execution (first two)
    const entryStages = KILL_CHAIN_STAGES.slice(0, 2);
    const chains = [];
    const seenChainKeys = new Set();

    for (const entryStage of entryStages) {
        for (const entryVuln of vulnsByStage[entryStage]) {
            // Greedy forward walk from this entry CVE
            const steps = [{ vuln: entryVuln, stage: entryStage }];
            const usedIds = new Set([entryVuln.id]);
            const entryStageIdx = STAGE_INDEX[entryStage];

            for (let i = entryStageIdx + 1; i < KILL_CHAIN_STAGES.length; i++) {
                const stage = KILL_CHAIN_STAGES[i];
                const candidates = vulnsByStage[stage].filter(v => !usedIds.has(v.id));
                if (candidates.length === 0) continue;

                // Prefer cross-asset hops
                const lastAsset = steps[steps.length - 1].vuln.asset;
                const crossAsset = candidates.find(v => v.asset && v.asset !== lastAsset);
                const pick = crossAsset || candidates[0];

                steps.push({ vuln: pick, stage });
                usedIds.add(pick.id);
            }

            // Only keep chains spanning 3+ stages
            if (steps.length < 3) continue;

            // Deduplicate by sorted CVE ID set
            const chainKey = steps.map(s => s.vuln.id).sort().join('|');
            if (seenChainKeys.has(chainKey)) continue;
            seenChainKeys.add(chainKey);

            const chain = {
                id: `chain-${chains.length + 1}`,
                stages: steps.map(s => s.stage),
                steps: steps.map(s => ({
                    cveId: s.vuln.id,
                    stage: s.stage,
                    asset: s.vuln.asset || 'Unknown',
                    cvssScore: s.vuln.cvssScore || 0,
                    epssScore: s.vuln.epssScore || 0,
                    epssPercentile: s.vuln.epssPercentile || 0,
                    severity: s.vuln.severity || 'UNKNOWN',
                    activelyExploited: !!s.vuln.activelyExploited,
                    threatActors: s.vuln.threatActors || [],
                    description: s.vuln.description || '',
                    attackTechniques: s.vuln.attackTechniques || [],
                })),
            };

            chain.score = scoreChain(chain);
            chains.push(chain);
        }
    }

    // Sort by score descending, return top 20
    chains.sort((a, b) => b.score - a.score);
    return chains.slice(0, 20);
}

// ── Break the Chain Analysis ────────────────────────────────────────

function computeBreakRecommendations(chains) {
    const cveChainCount = {};

    for (const chain of chains) {
        for (const step of chain.steps) {
            if (!cveChainCount[step.cveId]) {
                cveChainCount[step.cveId] = {
                    cveId: step.cveId,
                    asset: step.asset,
                    stage: step.stage,
                    severity: step.severity,
                    cvssScore: step.cvssScore,
                    epssScore: step.epssScore,
                    chainsDisrupted: 0,
                    totalRiskReduction: 0,
                };
            }
            cveChainCount[step.cveId].chainsDisrupted++;
            cveChainCount[step.cveId].totalRiskReduction += chain.score;
        }
    }

    return Object.values(cveChainCount)
        .sort((a, b) => b.chainsDisrupted - a.chainsDisrupted || b.totalRiskReduction - a.totalRiskReduction)
        .slice(0, 10)
        .map((rec, i) => ({ ...rec, priority: i + 1 }));
}

// ── Stage Distribution ──────────────────────────────────────────────

function computeStageDistribution(vulns) {
    const dist = {};
    for (const stage of KILL_CHAIN_STAGES) {
        dist[stage] = 0;
    }

    for (const vuln of vulns) {
        const stages = classifyVuln(vuln);
        for (const stage of stages) {
            dist[stage]++;
        }
    }

    return dist;
}

// ── Main Compute Function ───────────────────────────────────────────

export function computeKillChains(vulnData, userAssets = null) {
    let vulns = vulnData?.all || [];

    // Filter by user assets if provided
    if (userAssets && Array.isArray(userAssets) && vulnData?.byAsset) {
        const allowedSet = new Set(userAssets);
        vulns = [];
        for (const [assetId, assetVulns] of Object.entries(vulnData.byAsset)) {
            if (allowedSet.has(assetId)) {
                vulns.push(...assetVulns);
            }
        }
    }

    // Only consider vulns with ATT&CK technique mappings
    const mappedVulns = vulns.filter(v =>
        Array.isArray(v.attackTechniques) && v.attackTechniques.length > 0
    );

    const chains = buildChains(mappedVulns);
    const breakRecommendations = computeBreakRecommendations(chains);
    const stageDistribution = computeStageDistribution(mappedVulns);

    const totalChains = chains.length;
    const avgScore = totalChains > 0
        ? Math.round(chains.reduce((sum, c) => sum + c.score, 0) / totalChains)
        : 0;
    const criticalChains = chains.filter(c => c.score >= 70).length;
    const coveredStages = Object.values(stageDistribution).filter(n => n > 0).length;

    return {
        chains,
        breakRecommendations,
        stageDistribution,
        summary: {
            totalChains,
            criticalChains,
            avgScore,
            coveredStages,
            totalStages: KILL_CHAIN_STAGES.length,
            vulnsAnalyzed: mappedVulns.length,
        },
    };
}

// ── Cached Wrapper ──────────────────────────────────────────────────

export async function getKillChains(timeRange) {
    const cacheKey = `killchain:${timeRange}`;

    let cached;
    try {
        cached = await cacheGet(cacheKey);
    } catch {
        // Database unavailable — fall through to compute from vuln data
    }
    if (cached) return cached;

    let vulnData;
    try {
        vulnData = await getVulnData(timeRange);
    } catch {
        // Database unavailable
        return null;
    }
    if (!vulnData) return null;

    const result = computeKillChains(vulnData);
    try {
        await cacheSet(cacheKey, result, CACHE_TTL);
    } catch {
        // Cache write failed — result is still valid
    }
    return result;
}
