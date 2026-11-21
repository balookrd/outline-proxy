import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  base: '/ui-assets/',            // assets served from an absolute prefix, outside /ss|/ws
  build: { outDir: 'dist', assetsDir: '.', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:9500',
      '/ss/dashboard/api': 'http://127.0.0.1:9500',
      '/ws/dashboard/api': 'http://127.0.0.1:9500',
    },
  },
});
