// Health check endpoint to diagnose deployment issues

export default async function handler(req, res) {
    const results = {
        timestamp: new Date().toISOString(),
        checks: {}
    };

    // Test 1: Environment variables
    results.checks.env = {
        UPSTASH_REDIS_REST_URL: !!process.env.UPSTASH_REDIS_REST_URL,
        UPSTASH_REDIS_REST_TOKEN: !!process.env.UPSTASH_REDIS_REST_TOKEN,
        NVD_API_KEY: !!process.env.NVD_API_KEY,
        CRON_SECRET: !!process.env.CRON_SECRET,
        FIRST_EPSS_API_KEY: !!process.env.FIRST_EPSS_API_KEY
    };

    // Test 2: Import Redis module
    try {
        const { redis, BATCH_SIZE, TOTAL_BATCHES } = await import('../server/lib/redis.js');
        results.checks.redisImport = {
            success: true,
            batchSize: BATCH_SIZE,
            totalBatches: TOTAL_BATCHES
        };

        // Test 3: Redis connection
        try {
            await redis.ping();
            results.checks.redisConnection = { success: true };
        } catch (error) {
            results.checks.redisConnection = {
                success: false,
                error: error.message
            };
        }
    } catch (error) {
        results.checks.redisImport = {
            success: false,
            error: error.message,
            stack: error.stack
        };
    }

    // Test 4: Import assets
    try {
        const { ASSETS } = await import('../server/lib/assets.js');
        results.checks.assetsImport = {
            success: true,
            assetCount: ASSETS.length
        };
    } catch (error) {
        results.checks.assetsImport = {
            success: false,
            error: error.message
        };
    }

    // Test 5: Import nvdService
    try {
        const nvdService = await import('../server/lib/nvdService.js');
        results.checks.nvdServiceImport = {
            success: true,
            exports: Object.keys(nvdService)
        };
    } catch (error) {
        results.checks.nvdServiceImport = {
            success: false,
            error: error.message,
            stack: error.stack
        };
    }

    // Test 6: Import epssService
    try {
        const epssService = await import('../server/lib/epssService.js');
        results.checks.epssServiceImport = { success: true };
    } catch (error) {
        results.checks.epssServiceImport = {
            success: false,
            error: error.message
        };
    }

    // Test 7: Import attackMapping
    try {
        const attackMapping = await import('../server/lib/attackMapping.js');
        results.checks.attackMappingImport = { success: true };
    } catch (error) {
        results.checks.attackMappingImport = {
            success: false,
            error: error.message
        };
    }

    // Test 8: Import threatActorService
    try {
        const threatActorService = await import('../server/lib/threatActorService.js');
        results.checks.threatActorServiceImport = { success: true };
    } catch (error) {
        results.checks.threatActorServiceImport = {
            success: false,
            error: error.message
        };
    }

    // Overall status
    const allChecks = Object.values(results.checks);
    const failedChecks = allChecks.filter(check =>
        typeof check === 'object' && check.success === false
    );

    results.status = failedChecks.length === 0 ? 'healthy' : 'unhealthy';
    results.failedCount = failedChecks.length;
    results.totalChecks = allChecks.length;

    res.status(results.status === 'healthy' ? 200 : 500).json(results);
}
