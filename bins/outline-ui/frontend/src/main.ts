import { mount } from 'svelte'
import './app.css'
// Self-hosted fonts (fontsource) — see the comment in app.css for why these
// live here as JS-level imports rather than a CSS `@import`.
import '@fontsource/fira-sans/400.css'
import '@fontsource/fira-sans/500.css'
import '@fontsource/fira-sans/600.css'
import '@fontsource/fira-sans/700.css'
import '@fontsource/fira-code/400.css'
import '@fontsource/fira-code/500.css'
import '@fontsource/fira-code/600.css'
import App from './App.svelte'
import { applyTheme } from './lib/theme.svelte'

// Stamp data-theme before the first component mounts so the initial paint
// already matches the persisted/default preference (see lib/theme.svelte.ts).
applyTheme()

const app = mount(App, {
  target: document.getElementById('app')!,
})

export default app
