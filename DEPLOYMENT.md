# Deployment Guide

## Post-Deployment Cache Initialization

After deploying to Vercel, the Redis cache will be empty until the cron job runs. This results in the frontend showing **0 vulnerabilities** even though the app loads successfully.

### The Issue

- **Cron Schedule**: The cache refresh cron job runs **once per hour** (at the top of each hour)
- **Batched Processing**: Each cron run processes 4 assets out of 26 total
- **Full Cycle**: It takes 7 cron runs to fully populate the cache
- **Time to Full Cache**: Up to 7 hours for the first full cache population

### Quick Fix: Manual Cache Population

Use the provided script to manually trigger all 7 batches immediately after deployment:

```bash
# Without CRON_SECRET (if not set in Vercel env vars)
./scripts/trigger-cache-refresh.sh https://your-app.vercel.app

# With CRON_SECRET (if set in Vercel env vars)
./scripts/trigger-cache-refresh.sh https://your-app.vercel.app your-cron-secret
```

This will:
1. Trigger the `/api/cron/refresh` endpoint 7 times
2. Each call processes 4 assets
3. Takes about 15-20 seconds total
4. Fully populates the Redis cache

### Alternative: Wait for Automatic Population

If you don't want to manually trigger, just wait:
- **First vulnerabilities**: Will appear after the first cron run (top of the next hour)
- **Full data**: Will be complete after 7 hours

### Verifying Cache Population

After running the script, check:

1. **Frontend**: Refresh your app - you should see vulnerabilities
2. **API Endpoint**: Visit `https://your-app.vercel.app/api/vulnerabilities?timeRange=7d`
3. **Logs**: Check Vercel function logs for the cron endpoint

### Environment Variables Required

Make sure these are set in your Vercel project settings:

- `UPSTASH_REDIS_REST_URL` - Your Upstash Redis URL
- `UPSTASH_REDIS_REST_TOKEN` - Your Upstash Redis token
- `CRON_SECRET` (optional) - If set, required for manual cron triggers
- `NVD_API_KEY` (optional) - NVD API key for higher rate limits
- `FIRST_EPSS_API_KEY` (optional) - FIRST EPSS API key

### Troubleshooting

**Still showing 0 vulnerabilities after running the script?**

1. Check Vercel function logs for errors
2. Verify environment variables are set correctly
3. Check Redis connection:
   ```bash
   curl https://your-app.vercel.app/api/vulnerabilities?timeRange=24h
   ```
4. Look for error responses indicating missing env vars or connection issues

**Cron job not running automatically?**

1. Verify `vercel.json` has the cron configuration
2. Check that you're on a Vercel plan that supports cron jobs
3. Cron jobs only run on production deployments, not preview deployments

### Cron Schedule Configuration

Current schedule (in `vercel.json`):

```json
{
  "crons": [
    {
      "path": "/api/cron/refresh",
      "schedule": "0 * * * *"  // Every hour at :00
    }
  ]
}
```

**Cron Schedule Examples:**
- `"0 * * * *"` - Every hour at :00 (current)
- `"*/30 * * * *"` - Every 30 minutes
- `"0 */6 * * *"` - Every 6 hours
- `"0 1 * * *"` - Once daily at 1:00 AM

**Note**: More frequent schedules consume more Vercel function invocations and NVD API calls.

## Initial Deployment Checklist

- [ ] Set all required environment variables in Vercel
- [ ] Deploy to production
- [ ] Run `scripts/trigger-cache-refresh.sh` to populate cache
- [ ] Verify app shows vulnerabilities
- [ ] Monitor first automatic cron run in Vercel logs

## Monitoring

- **Cache Status**: `/api/vulnerabilities?timeRange=7d` should return data
- **Vercel Logs**: Monitor the `/api/cron/refresh` function logs
- **Redis**: Check Upstash dashboard for key counts and memory usage
