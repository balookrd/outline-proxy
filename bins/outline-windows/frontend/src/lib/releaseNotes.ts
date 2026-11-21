export type NoteLine =
  | { kind: 'header'; text: string }
  | { kind: 'bullet'; text: string }
  | { kind: 'text'; text: string };

/**
 * Turns a GitHub release body (Markdown produced by git-cliff) into a flat
 * list of displayable lines for the update modal, matching Android's
 * `ReleaseNotes.kt` and macOS's `ReleaseNotes.swift`.
 *
 * Returns an empty list when there is nothing user-facing to show — an empty
 * body, a no-changes fallback notice, or only a compare link — so the modal
 * hides the changelog block cleanly.
 */
export function formatReleaseNotes(raw: string): NoteLine[] {
  const lines: NoteLine[] = [];

  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    // Checked before the level-2 rule so `### ` is never mistaken for `## `.
    if (line.startsWith('### ')) {
      lines.push({ kind: 'header', text: stripInline(line.slice(4)) });
    } else if (line.startsWith('## ')) {
      // `## What's Changed in <tag>` duplicates the modal title.
      continue;
    } else if (line.startsWith('**Full Changelog**')) {
      // Technical compare link, not a user-facing change.
      continue;
    } else if (line.startsWith('- ') || line.startsWith('* ')) {
      lines.push({ kind: 'bullet', text: stripInline(line.slice(2)) });
    } else {
      const prev = lines.at(-1);
      if (prev?.kind === 'bullet') {
        // git-cliff wraps long entries; a continuation line belongs to the bullet above it.
        lines[lines.length - 1] = {
          kind: 'bullet',
          text: `${prev.text} ${stripInline(line)}`,
        };
      } else {
        lines.push({ kind: 'text', text: stripInline(line) });
      }
    }
  }

  const structured = lines.some((line) => line.kind !== 'text');
  return structured ? lines : [];
}

/** Strip the inline markup git-cliff emits: bold `**…**`. */
function stripInline(s: string): string {
  return s.replaceAll('**', '').trim();
}
