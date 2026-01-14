import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    open: true,
    proxy: {
      '/api/nvd': {
        target: 'https://services.nvd.nist.gov',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/nvd/, '/rest/json/cves/2.0'),
        secure: true
      }
    }
  }
})
