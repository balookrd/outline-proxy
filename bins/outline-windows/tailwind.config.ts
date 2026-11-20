import type { Config } from 'tailwindcss';

export default {
  content: ['./frontend/index.html', './frontend/src/**/*.{svelte,js,ts}'],
  theme: {
    extend: {},
  },
  plugins: [],
} satisfies Config;
