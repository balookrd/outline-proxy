<script lang="ts">
  import { buildQrMatrix, qrPathData } from '../../lib/qr';

  let {
    value,
    label = 'Access key QR code',
    size = 180,
  }: {
    value: string;
    label?: string;
    size?: number;
  } = $props();

  const qr = $derived(buildQrMatrix(value));
  const pathD = $derived(qrPathData(qr.rows));
</script>

<div class="qr-box">
  <svg
    width={size}
    height={size}
    viewBox={`0 0 ${qr.size} ${qr.size}`}
    role="img"
    aria-label={label}
    shape-rendering="crispEdges"
  >
    <rect width={qr.size} height={qr.size} fill="#ffffff" />
    <path d={pathD} fill="#0f172a" />
  </svg>
</div>
