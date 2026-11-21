import { listClusters, listInstances } from './api';
import type { ClusterSummary, Instance, SsTarget } from './types';

export const ssTargetState = $state<{
  instances: Instance[];
  clusters: ClusterSummary[];
  target: SsTarget | null;
  refreshSecs: number;
  loaded: boolean;
  error: string | null;
}>({
  instances: [],
  clusters: [],
  target: null,
  refreshSecs: 5,
  loaded: false,
  error: null,
});

export function isValidSsTarget(
  target: SsTarget | null,
  clusters: ClusterSummary[],
  instances: Instance[],
): boolean {
  if (!target) return false;
  if (target.kind === 'cluster') return clusters.some((c) => c.name === target.name);
  return instances.some((i) => i.name === target.name);
}

export function pickDefaultSsTarget(
  clusters: ClusterSummary[],
  instances: Instance[],
): SsTarget | null {
  if (clusters.length > 0) return { kind: 'cluster', name: clusters[0].name };
  if (instances.length > 0) return { kind: 'instance', name: instances[0].name };
  return null;
}

export function findClusterForInstance(instanceName: string): ClusterSummary | null {
  return ssTargetState.clusters.find((c) => c.members.includes(instanceName)) ?? null;
}

export function getClusterSummary(clusterName: string): ClusterSummary | null {
  return ssTargetState.clusters.find((c) => c.name === clusterName) ?? null;
}

export function getInstanceInfo(instanceName: string): Instance | null {
  return ssTargetState.instances.find((i) => i.name === instanceName) ?? null;
}

let inflight: Promise<void> | null = null;
let subscribers = 0;
let pollTimer: ReturnType<typeof setTimeout> | null = null;

export async function refreshSsTargets(): Promise<void> {
  if (inflight) return inflight;
  inflight = (async () => {
    try {
      const [instRes, clusterRes] = await Promise.all([
        listInstances('/ss'),
        listClusters().catch(() => null),
      ]);
      ssTargetState.instances = instRes.instances ?? [];
      if (instRes.refresh_interval_secs > 0) {
        ssTargetState.refreshSecs = instRes.refresh_interval_secs;
      }
      ssTargetState.clusters = clusterRes?.clusters ?? instRes.clusters ?? [];
      if (!isValidSsTarget(ssTargetState.target, ssTargetState.clusters, ssTargetState.instances)) {
        ssTargetState.target = pickDefaultSsTarget(ssTargetState.clusters, ssTargetState.instances);
      }
      ssTargetState.error = null;
      ssTargetState.loaded = true;
    } catch (e) {
      ssTargetState.error = e instanceof Error ? e.message : String(e);
      ssTargetState.loaded = true;
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

function scheduleNext() {
  if (pollTimer) clearTimeout(pollTimer);
  if (subscribers <= 0) return;
  const interval = Math.max(5000, ssTargetState.refreshSecs * 1000);
  pollTimer = setTimeout(async () => {
    if (typeof document === 'undefined' || !document.hidden) {
      await refreshSsTargets();
    }
    scheduleNext();
  }, interval);
}

export function subscribeSsTargets(): () => void {
  subscribers++;
  if (subscribers === 1) {
    refreshSsTargets().then(() => scheduleNext());
  }
  return () => {
    subscribers = Math.max(0, subscribers - 1);
    if (subscribers === 0 && pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }
  };
}
