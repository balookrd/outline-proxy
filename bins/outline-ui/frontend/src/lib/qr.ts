import { encode } from 'uqr';

export interface QrMatrix {
  size: number;
  rows: boolean[][];
}

export function buildQrMatrix(text: string): QrMatrix {
  const result = encode(text, { ecc: 'M', border: 4 });
  return {
    size: result.size,
    rows: result.data,
  };
}

/// Encodes all dark modules as one compact SVG path string with integer
/// module coordinates (0..size), so rendering needs zero per-cell DOM nodes
/// and zero `{@html}` injection.
export function qrPathData(rows: boolean[][]): string {
  const parts: string[] = [];
  for (let y = 0; y < rows.length; y++) {
    const row = rows[y];
    let x = 0;
    while (x < row.length) {
      if (!row[x]) {
        x++;
        continue;
      }
      let run = 1;
      while (x + run < row.length && row[x + run]) {
        run++;
      }
      parts.push(`M${x} ${y}h${run}v1h-${run}z`);
      x += run;
    }
  }
  return parts.join('');
}
