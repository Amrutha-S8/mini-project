/**
 * Design tokens taken from the approved reference image: deep navy and black
 * background, neon blue, cyan, purple and green highlights, glass cards with
 * glowing borders. Option A feeds these into Tailwind and the Three.js scenes,
 * so every page shares one palette.
 *
 * Colour values are estimated by eye from the reference. `tokens.test.ts`
 * checks text contrast (WCAG 2.2) against the actual backgrounds, including
 * the translucent glass cards composited over the page background.
 */

export const color = {
  bg: {
    base: "#050816",
    deep: "#03050f",
    raised: "#0a1030",
  },
  /** Glass card: translucent fill over `bg.base`, plus blur in CSS. */
  glass: {
    fill: "rgba(16, 26, 70, 0.55)",
    fillStrong: "rgba(22, 34, 92, 0.72)",
    border: "rgba(82, 140, 255, 0.35)",
    borderActive: "rgba(56, 189, 248, 0.75)",
  },
  neon: {
    blue: "#3b82f6",
    cyan: "#22d3ee",
    purple: "#8b5cf6",
    green: "#22c55e",
    magenta: "#d946ef",
  },
  text: {
    primary: "#e8eeff",
    secondary: "#b4c0e4",
    muted: "#8e9cc6",
    onAccent: "#04101f",
  },
  /** Status tones. Access outcomes are shown, never decided, by the UI. */
  status: {
    allow: "#22c55e",
    deny: "#f43f5e",
    hold: "#f59e0b",
    info: "#38bdf8",
    unavailable: "#7c88b0",
  },
  severity: {
    info: "#38bdf8",
    low: "#22c55e",
    medium: "#f59e0b",
    high: "#f97316",
    critical: "#f43f5e",
  },
  /** Initials-avatar backgrounds (no face photos, SR-STORE-03). */
  avatar: ["#2563eb", "#7c3aed", "#0891b2", "#059669", "#c026d3", "#4f46e5"],
} as const;

export const radius = { sm: "8px", md: "12px", lg: "16px", xl: "22px", pill: "999px" } as const;

export const spacing = {
  xs: "4px",
  sm: "8px",
  md: "12px",
  lg: "16px",
  xl: "24px",
  xxl: "32px",
  sidebar: "232px",
} as const;

export const typography = {
  family: {
    sans: '"Inter", "Segoe UI", system-ui, -apple-system, sans-serif',
    display: '"Orbitron", "Inter", "Segoe UI", system-ui, sans-serif',
    mono: '"JetBrains Mono", "Cascadia Code", ui-monospace, monospace',
  },
  size: { xs: "12px", sm: "13px", md: "15px", lg: "18px", xl: "24px", xxl: "32px" },
  weight: { regular: 400, medium: 500, semibold: 600, bold: 700 },
} as const;

export const shadow = {
  card: "0 8px 32px rgba(2, 6, 23, 0.55)",
  glowBlue: "0 0 24px rgba(59, 130, 246, 0.45)",
  glowCyan: "0 0 22px rgba(34, 211, 238, 0.45)",
  glowPurple: "0 0 26px rgba(139, 92, 246, 0.45)",
  glowGreen: "0 0 20px rgba(34, 197, 94, 0.45)",
} as const;

export const blur = { glass: "16px" } as const;

export interface MotionSettings {
  readonly pageTransitionMs: number;
  readonly hoverMs: number;
  readonly chartMs: number;
  /** Holographic face scanner (Three.js) behaviour. */
  readonly scannerRotates: boolean;
  readonly scannerBeam: boolean;
  readonly maxParticles: number;
}

/** Normal motion. Particle budgets keep the GPU free for the webcam page. */
export const motion: MotionSettings = {
  pageTransitionMs: 280,
  hoverMs: 160,
  chartMs: 600,
  scannerRotates: true,
  scannerBeam: true,
  maxParticles: 600,
};

/** `prefers-reduced-motion` or the in-app toggle: no movement at all. */
export const reducedMotion: MotionSettings = {
  pageTransitionMs: 0,
  hoverMs: 0,
  chartMs: 0,
  scannerRotates: false,
  scannerBeam: false,
  maxParticles: 0,
};

/** The live webcam page gets a smaller 3D budget so video stays smooth. */
export const MONITORING_PARTICLE_BUDGET = 150;

export function motionFor(opts: { reduced: boolean; page?: string }): MotionSettings {
  if (opts.reduced) return reducedMotion;
  if (opts.page === "live_monitoring") {
    return { ...motion, maxParticles: Math.min(motion.maxParticles, MONITORING_PARTICLE_BUDGET) };
  }
  return motion;
}

export const tokens = { color, radius, spacing, typography, shadow, blur } as const;

// --- CSS custom properties -------------------------------------------------------

function kebab(text: string): string {
  return text.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
}

function flatten(prefix: string, value: unknown, out: [string, string][]): void {
  if (typeof value === "string" || typeof value === "number") {
    out.push([prefix, String(value)]);
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => flatten(`${prefix}-${i}`, v, out));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) flatten(`${prefix}-${kebab(k)}`, v, out);
  }
}

/** `:root { --color-bg-base: #050816; ... }`, sorted, for the Option A stylesheet. */
export function toCssVariables(): string {
  const pairs: [string, string][] = [];
  for (const [group, value] of Object.entries(tokens)) flatten(`--${group}`, value, pairs);
  pairs.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `:root {\n${pairs.map(([k, v]) => `  ${k}: ${v};`).join("\n")}\n}\n`;
}

// --- contrast (WCAG 2.2) ---------------------------------------------------------

export interface Rgba {
  r: number;
  g: number;
  b: number;
  a: number;
}

export function parseColor(text: string): Rgba {
  const hex = /^#([0-9a-f]{6})$/i.exec(text);
  if (hex?.[1]) {
    const n = parseInt(hex[1], 16);
    return { r: (n >> 16) & 255, g: (n >> 8) & 255, b: n & 255, a: 1 };
  }
  const rgba = /^rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)$/.exec(text);
  if (rgba) {
    return {
      r: Number(rgba[1]),
      g: Number(rgba[2]),
      b: Number(rgba[3]),
      a: rgba[4] === undefined ? 1 : Number(rgba[4]),
    };
  }
  throw new Error(`unsupported colour: ${text}`);
}

/** Source-over composite of a translucent colour on an opaque one. */
export function composite(top: Rgba, bottom: Rgba): Rgba {
  const mix = (t: number, b: number): number => t * top.a + b * (1 - top.a);
  return { r: mix(top.r, bottom.r), g: mix(top.g, bottom.g), b: mix(top.b, bottom.b), a: 1 };
}

function luminance(c: Rgba): number {
  const lin = (v: number): number => {
    const s = v / 255;
    return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
}

export function contrastRatio(fg: Rgba, bg: Rgba): number {
  const [hi, lo] = [luminance(fg), luminance(bg)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}
