import { describe, it, expect } from 'vitest';
import { buildQrMatrix, qrPathData } from './qr';

describe('qr encoder wrapper', () => {
  it('encodes payload with a >= 4 module quiet-zone border', () => {
    const matrix = buildQrMatrix('ssconf://edge.fleet.example/alice.conf');
    expect(matrix.size).toBeGreaterThanOrEqual(29); // 21 (v1) + 4*2 border
    expect(matrix.rows.length).toBe(matrix.size);
    // Top 4 and bottom 4 border rows must be all white (false)
    for (let borderRow = 0; borderRow < 4; borderRow++) {
      expect(matrix.rows[borderRow].every((cell) => !cell)).toBe(true);
      expect(matrix.rows[matrix.size - 1 - borderRow].every((cell) => !cell)).toBe(true);
    }
    const path = qrPathData(matrix.rows);
    expect(path.startsWith('M4 4h')).toBe(true);
    expect(path.length).toBeGreaterThan(20);
  });
});
