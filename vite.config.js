import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Set base path for deployment at a subpath (e.g., yoursite.com/heimdall/)
  // Change this to match your deployment path, or use '/' for root deployment
  base: '/heimdall/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets'
  },
  // Backend API URL - set via environment variable for production
  // In production, this points to your Railway/Render/Vercel backend
  define: {
    'import.meta.env.VITE_API_URL': JSON.stringify(process.env.VITE_API_URL || '')
  },
  server: {
    port: 5173,
    open: true,
    proxy: {
      '/api/nvd': {
        target: 'https://services.nvd.nist.gov',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/nvd/, '/rest/json/cves/2.0'),
        secure: true
      },
      '/api/cisa': {
        target: 'https://www.cisa.gov',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/cisa/, '/sites/default/files/feeds'),
        secure: true
      }
    }
  }
})
