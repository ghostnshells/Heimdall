// Vercel Cron Function — batched NVD vulnerability refresh
// Runs every 10 minutes, processes 4 assets per run
// Full refresh cycle completes in ~50 minutes (5 batches × 10 min)

import { ASSETS } from '../lib/assets.js';
import {
    fetchVulnerabilitiesForAsset,
    searchCISAForAsset,
    sortByMostRecentDate,
    getDateRange
} from '../lib/nvdService.js';
import {
    setAssetVulns,
    assembleFullCache,
    getBatchIndex,
    incrementBatchIndex,
    BATCH_SIZE
} from '../lib/redis.js';
import { enrichWithEPSS } from '../lib/epssService.js';
import { enrichWithAttackTechniques } from '../lib/attackMapping.js';
import { enrichWithThreatActors } from '../lib/threatActorService.js';

const TIME_RANGES = ['24h', '7d', '30d', '90d', '119d'];

export default async function handler(req, res) {
    // Verify this is a legitimate cron invocation
    const authHeader = req.headers['authorization'];
    const cronSecret = process.env.CRON_SECRET;

    if (cronSecret && authHeader !== `Bearer ${cronSecret}`) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
        const batchIndex = await getBatchIndex();
        const startIdx = batchIndex * BATCH_SIZE;
        const batchAssets = ASSETS.slice(startIdx, startIdx + BATCH_SIZE);

        if (batchAssets.length === 0) {
            // All batches done, reset to 0
            await incrementBatchIndex();
            return res.json({
                success: true,
                message: 'No assets in this batch (resetting index)',
                batchIndex,
                nextBatchIndex: 0
            });
        }

        console.log(`[Cron] Batch ${batchIndex}: processing ${batchAssets.length} assets (${batchAssets.map(a => a.name).join(', ')})`);

        // Process each asset in this batch for all time ranges
        for (const asset of batchAssets) {
            for (const timeRange of TIME_RANGES) {
                try {
                    const { startDate, endDate } = getDateRange(timeRange);

                    // Fetch from NVD
                    const nvdVulns = await fetchVulnerabilitiesForAsset(asset, startDate, endDate);

                    // Fetch from CISA
                    let cisaVulns = [];
                    try {
                        cisaVulns = await searchCISAForAsset(asset, startDate, endDate);
                    } catch (e) {
                        console.warn(`[Cron] CISA failed for ${asset.name}: ${e.message}`);
                    }

                    // Merge NVD + CISA
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

                    const sorted = sortByMostRecentDate(merged);

                    // Enrich with ATT&CK technique mappings (synchronous, no API call)
                    const withAttack = enrichWithAttackTechniques(sorted);

                    // Enrich with EPSS scores (async, batched API call)
                    const enriched = await enrichWithEPSS(withAttack);
                    const withThreatActors = enrichWithThreatActors(enriched);

                    // Store per-asset results in Redis
                    await setAssetVulns(asset.id, timeRange, withThreatActors);

                    console.log(`[Cron] ${asset.name} (${timeRange}): ${withThreatActors.length} vulnerabilities`);
                } catch (error) {
                    console.error(`[Cron] Error for ${asset.name} (${timeRange}):`, error.message);
                    // Store empty array so assembly still works
                    await setAssetVulns(asset.id, timeRange, []);
                }
            }
        }

        // Reassemble full cache for all time ranges
        for (const timeRange of TIME_RANGES) {
            await assembleFullCache(timeRange, ASSETS);
        }

        // Advance to next batch
        const nextBatchIndex = await incrementBatchIndex();

        res.json({
            success: true,
            batchIndex,
            nextBatchIndex,
            assetsProcessed: batchAssets.map(a => a.name),
            totalAssets: ASSETS.length
        });
    } catch (error) {
        console.error('[Cron] Refresh failed:', error);
        res.status(500).json({ error: 'Refresh failed', message: error.message });
    }
}
