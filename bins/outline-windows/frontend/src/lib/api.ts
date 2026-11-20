import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type {
  ServerProfile,
  ProcessState,
  ConnectionStatusResponse,
  AppSettings,
} from './types';

/**
 * Fetch the current connection status and active profile info.
 */
export async function getStatus(): Promise<ConnectionStatusResponse> {
  return invoke<ConnectionStatusResponse>('get_status');
}

/**
 * Start proxy connection. Optionally selects profile_id first.
 */
export async function connect(profileId?: string): Promise<void> {
  return invoke('connect', { profileId });
}

/**
 * Disconnect active proxy and restore system proxy.
 */
export async function disconnect(): Promise<void> {
  return invoke('disconnect');
}

/**
 * Fetch all configured server profiles.
 */
export async function getProfiles(): Promise<ServerProfile[]> {
  return invoke<ServerProfile[]>('get_profiles');
}

/**
 * Parse and add a new server profile from link or subscription URL.
 */
export async function addProfile(link: string): Promise<ServerProfile> {
  return invoke<ServerProfile>('add_profile', { link });
}

/**
 * Remove a server profile by its ID.
 */
export async function removeProfile(id: string): Promise<void> {
  return invoke('remove_profile', { id });
}

/**
 * Select the active profile by ID.
 */
export async function selectProfile(id: string): Promise<void> {
  return invoke('select_profile', { id });
}

/**
 * Get the current in-memory log buffer.
 */
export async function getLogs(): Promise<string[]> {
  return invoke<string[]>('get_logs');
}

/**
 * Get current application settings.
 */
export async function getSettings(): Promise<AppSettings> {
  return invoke<AppSettings>('get_settings');
}

/**
 * Update application settings.
 */
export async function updateSettings(settings: AppSettings): Promise<void> {
  return invoke('update_settings', { settings });
}

/**
 * Trigger remote fetch for subscription and update cached configuration.
 */
export async function updateSubscription(profileId: string): Promise<number> {
  return invoke<number>('update_subscription', { profileId });
}

/**
 * Listen for real-time status change events emitted by background process controller.
 */
export async function onStatusChanged(
  handler: (state: ProcessState) => void,
): Promise<UnlistenFn> {
  return listen<ProcessState>('status-changed', (event) => {
    handler(event.payload);
  });
}

/**
 * Listen for live stdout/stderr log stream messages.
 */
export async function onLogMessage(
  handler: (message: string) => void,
): Promise<UnlistenFn> {
  return listen<string>('log-message', (event) => {
    handler(event.payload);
  });
}

/**
 * Listen for profile list modifications (added, removed, selected, subscription updated).
 */
export async function onProfilesUpdated(
  handler: () => void,
): Promise<UnlistenFn> {
  return listen<void>('profiles-updated', () => {
    handler();
  });
}

/**
 * Listen for settings modifications.
 */
export async function onSettingsUpdated(
  handler: () => void,
): Promise<UnlistenFn> {
  return listen<void>('settings-updated', () => {
    handler();
  });
}

/**
 * Listen for tray navigation commands ('settings' | 'logs').
 */
export async function onNavigate(
  handler: (target: 'settings' | 'logs') => void,
): Promise<UnlistenFn> {
  return listen<string>('navigate', (event) => {
    if (event.payload === 'settings' || event.payload === 'logs') {
      handler(event.payload);
    }
  });
}
