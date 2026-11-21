/**
 * Server profile representation from the backend store.
 */
export interface ServerProfile {
  id: string;
  name: string;
  transport: 'vless' | 'ss' | 'subscription' | string;
  link?: string;
  paddingEnabled?: boolean;
  padding_enabled?: boolean;
  tcpOnly?: boolean;
  tcp_only?: boolean;
  rawTomlOverride?: string;
  raw_toml_override?: string;
  configUrl?: string;
  config_url?: string;
  cachedToml?: string;
  cached_toml?: string;
  updatedAt?: number;
  updated_at?: number;
  ping?: number | null;
}

/**
 * Process state tagged enum matching Rust serde representation.
 */
export type ProcessState =
  | { status: 'stopped'; data?: never }
  | { status: 'starting'; data?: never }
  | { status: 'running'; data: { pid: number } }
  | { status: 'stopping'; data?: never }
  | { status: 'error'; data: string };

/**
 * Comprehensive connection status returned by Tauri commands and events.
 */
export interface ConnectionStatusResponse {
  state: ProcessState;
  activeProfileId?: string | null;
  active_profile_id?: string | null;
  activeProfileName?: string | null;
  active_profile_name?: string | null;
  mode: 'socks5' | 'tun' | string;
  tcpOnly?: boolean;
  tcp_only?: boolean;
  uptimeSecs?: number | null;
  uptime_secs?: number | null;
  txBytes?: number;
  tx_bytes?: number;
  rxBytes?: number;
  rx_bytes?: number;
}

/**
 * Application settings for Windows client.
 */
export interface AppSettings {
  proxyMode: 'socks5' | 'tun';
  tcpOnly: boolean;
  socksPort: number;
  autostart: boolean;
  startMinimized: boolean;
  reconnectAfterUpdate?: boolean;
}

/**
 * Version and build metadata of the desktop application.
 */
export interface AppVersionInfo {
  version: string;
  commit: string;
  channel: string;
  displayString: string;
  display_string?: string;
}

/**
 * Metadata for an available application update.
 */
export interface UpdateInfo {
  label: string;
  assetName: string;
  asset_name?: string;
  downloadUrl: string;
  download_url?: string;
  checksumsUrl?: string | null;
  checksums_url?: string | null;
  notes: string;
  commit: string;
}

/**
 * Result of checking for updates against remote GitHub releases.
 */
export type UpdateCheckResult =
  | { status: 'upToDate' }
  | { status: 'available'; update: UpdateInfo };

/**
 * Progress payload emitted during download and extraction.
 */
export interface UpdateProgressEvent {
  downloaded: number;
  total: number;
  percent: number;
}

/**
 * Helper predicates for ProcessState.
 */
export function isProcessRunning(state: ProcessState): boolean {
  return state.status === 'running';
}

export function isProcessStarting(state: ProcessState): boolean {
  return state.status === 'starting';
}

export function isProcessStopping(state: ProcessState): boolean {
  return state.status === 'stopping';
}

export function isProcessStopped(state: ProcessState): boolean {
  return state.status === 'stopped';
}

export function isProcessError(state: ProcessState): boolean {
  return state.status === 'error';
}

export function isProcessBusy(state: ProcessState): boolean {
  return state.status === 'starting' || state.status === 'stopping';
}
