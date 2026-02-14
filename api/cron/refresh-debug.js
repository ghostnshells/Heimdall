// TEMPORARY DEBUG ENDPOINT - Remove after cache is populated
// This endpoint has NO authentication for testing purposes

import { ASSETS } from '../../server/lib/assets.js';
import {
    fetchVulnerabilitiesForAsset,
    searchCISAForAsset,
    sortByMostRecentDate,
    getDateRange
} from '../../server/lib/nvdService.js';
import {
    setAssetVulns,
    assembleFullCache,
    getBatchIndex,
    incrementBatchIndex,
    BATCH_SIZE
} from '../../server/lib/redis.js';
import { enrichWithEPSS } from '../../server/lib/epssService.js';
import { enrichWithAttackTechniques } from '../../server/lib/attackMapping.js';
import { enrichWithThreatActors } from '../../server/lib/threatActorService.js';

const TIME_RANGES = ['24h', '7d', '30d', '90d', '119d'];

export default async function handler(req, res) {
    console.log('[Debug Cron] Starting batch refresh (NO AUTH)...');

    try {
        const batchIndex = await getBatchIndex();
        const startIdx = batchIndex * BATCH_SIZE;
        const batchAssets = ASSETS.slice(startIdx, startIdx + BATCH_SIZE);

        if (batchAssets.length === 0) {
            await incrementBatchIndex();
            return res.json({
                success: true,
                message: 'No assets in this batch (resetting index)',
                batchIndex,
                nextBatchIndex: 0
            });
        }

        console.log(`[Debug Cron] Batch ${batchIndex}: processing ${batchAssets.length} assets`);

        for (const asset of batchAssets) {
            for (const timeRange of TIME_RANGES) {
                try {
                    const { startDate, endDate } = getDateRange(timeRange);
                    const nvdVulns = await fetchVulnerabilitiesForAsset(asset, startDate, endDate);

                    let cisaVulns = [];
                    try {
                        cisaVulns = await searchCISAForAsset(asset, startDate, endDate);
                    } catch (e) {
                        console.warn(`[Debug Cron] CISA failed for ${asset.name}: ${e.message}`);
                    }

                    const cisaVulnMap = new Map(cisaVulns.map(v => [v.id, v]));
                    const merged = nvdVulns.map(vuln => {
                        const cisaVuln = cisaVulnMap.get(vuln.id);
                        return {
                            ...vuln,
                            activelyExploited: cisaVuln ? true : vuln.activelyExploited,
                            cisaData: cisaVuln?.cisaData || vuln.cisaData
                        };
                    });

                    const nvdIds = new Set(nvdVulns.map(v => v.id));
                    const cisaOnly = cisaVulns.filter(v => !nvdIds.has(v.id));
                    merged.push(...cisaOnly);

                    const sorted = sortByMostRecentDate(merged);
                    const withAttack = enrichWithAttackTechniques(sorted);
                    const enriched = await enrichWithEPSS(withAttack);
                    const withThreatActors = enrichWithThreatActors(enriched);

                    await setAssetVulns(asset.id, timeRange, withThreatActors);
                    console.log(`[Debug Cron] ${asset.name} (${timeRange}): ${withThreatActors.length} vulns`);
                } catch (error) {
                    console.error(`[Debug Cron] Error for ${asset.name} (${timeRange}):`, error.message);
                    await setAssetVulns(asset.id, timeRange, []);
                }
            }
        }

        for (const timeRange of TIME_RANGES) {
            await assembleFullCache(timeRange, ASSETS);
        }

        const nextBatchIndex = await incrementBatchIndex();

        res.json({
            success: true,
            batchIndex,
            nextBatchIndex,
            assetsProcessed: batchAssets.map(a => a.name),
            totalAssets: ASSETS.length,
            warning: 'This is a debug endpoint with NO authentication'
        });
    } catch (error) {
        console.error('[Debug Cron] Refresh failed:', error);
        res.status(500).json({ error: 'Refresh failed', message: error.message });
    }
}
