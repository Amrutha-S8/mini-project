/**
 * Initials avatars. The backend never returns face images (SR-STORE-03), so
 * every person is shown by initials, never by a photograph.
 */

const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });

function firstGrapheme(word: string): string {
  for (const { segment } of segmenter.segment(word)) return segment;
  return "";
}

/** "Test Owner" -> "TO", "Ana María López" -> "AL", "李小龍" -> "李". */
export function initials(fullName: string): string {
  const words = fullName
    .normalize("NFC")
    .split(/[\s\u00a0]+/)
    .map((w) => w.replace(/^[^\p{L}\p{N}]+/u, ""))
    .filter((w) => w.length > 0);
  if (words.length === 0) return "?";
  const first = firstGrapheme(words[0] ?? "");
  const last = words.length > 1 ? firstGrapheme(words[words.length - 1] ?? "") : "";
  return (first + last).toLocaleUpperCase();
}

/** Stable index into an avatar palette, so a person keeps their colour. */
export function avatarIndex(key: string, paletteSize: number): number {
  if (!Number.isInteger(paletteSize) || paletteSize < 1) throw new RangeError("paletteSize");
  let hash = 2166136261;
  for (const ch of key) {
    hash ^= ch.codePointAt(0) ?? 0;
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash % paletteSize;
}
