import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        // Keep Three.js + globe in its own lazy chunk so it doesn't block
        // initial page load (lazily imported via React.lazy in GlobeMap)
        manualChunks(id) {
          if (id.includes('react-globe.gl') || id.includes('three')) {
            return 'globe-vendor'
          }
        },
      },
    },
  },
})
