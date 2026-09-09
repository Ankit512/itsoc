import type { Config } from "tailwindcss";
import animate from "tailwindcss-animate";

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        card: { DEFAULT: "hsl(var(--card))", foreground: "hsl(var(--card-foreground))" },
        muted: { DEFAULT: "hsl(var(--muted))", foreground: "hsl(var(--muted-foreground))" },
        primary: { DEFAULT: "hsl(var(--primary))", foreground: "hsl(var(--primary-foreground))" },
        accent: { DEFAULT: "hsl(var(--accent))", foreground: "hsl(var(--accent-foreground))" },
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        // Severity status palette — validated for BOTH surfaces with the
        // dataviz six-checks script. G0 moved these roles into the
        // styles/itsoc.css token registry: --sev-* are compatibility aliases
        // onto the per-theme --severity-* roles declared there.
        sev: {
          critical: "var(--sev-critical)",
          high: "var(--sev-high)",
          medium: "var(--sev-medium)",
          low: "var(--sev-low)",
        },
      },
      borderRadius: { lg: "12px", md: "8px", sm: "6px" },
      // The v6 card shadow. Since G0, --shadow is a compatibility alias in
      // styles/itsoc.css onto the per-theme --elevation-card role.
      boxShadow: { card: "var(--shadow)" },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ["ui-monospace", "Menlo", "Monaco", "Cascadia Code", "monospace"],
      },
    },
  },
  plugins: [animate],
} satisfies Config;
