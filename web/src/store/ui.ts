import { create } from "zustand";

/** UI-only state. Server state lives in TanStack Query; nothing here decides
 *  anything about findings or severity. */

export type Theme = "light" | "dark";
const THEME_KEY = "itsoc-theme";
const EXPERIMENTAL_KEY = "itsoc-experimental";

/** Off by default — the fenced Command-Center pages (OEM Engine, History) stay
 *  out of the nav until the user opts in from Settings. */
function readInitialExperimental(): boolean {
  try {
    return localStorage.getItem(EXPERIMENTAL_KEY) === "1";
  } catch { /* storage unavailable */ }
  return false;
}

function readInitialTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch { /* storage unavailable */ }
  if (typeof matchMedia === "function"
      && matchMedia("(prefers-color-scheme: dark)").matches) return "dark";
  return "light";
}

export function applyThemeClass(theme: Theme) {
  document.documentElement.classList.toggle("dark", theme === "dark");
}

interface UiState {
  theme: Theme;
  sidebarOpen: boolean;
  timeWindow: string;
  search: string;
  /** Shows the fenced Command-Center pages (OEM Engine, History). Off by
   *  default; never re-enables the cut pages (Discovery/Vulnerabilities/
   *  Enrichment/Logout), which are removed outright. */
  experimental: boolean;
  setExperimental: (on: boolean) => void;
  toggleTheme: () => void;
  setSidebarOpen: (open: boolean) => void;
  setTimeWindow: (w: string) => void;
  setSearch: (s: string) => void;
  /** Clear local UI state to a neutral default — used by the honest Logout,
   *  which has no server session to end. Forgets the saved theme too. */
  resetUi: () => void;
}

export const useUi = create<UiState>((set, get) => ({
  theme: readInitialTheme(),
  sidebarOpen: true,
  timeWindow: "Current run",
  search: "",
  experimental: readInitialExperimental(),
  setExperimental: (experimental) => {
    try {
      if (experimental) localStorage.setItem(EXPERIMENTAL_KEY, "1");
      else localStorage.removeItem(EXPERIMENTAL_KEY);
    } catch { /* not persistable */ }
    set({ experimental });
  },
  toggleTheme: () => {
    const theme: Theme = get().theme === "dark" ? "light" : "dark";
    try { localStorage.setItem(THEME_KEY, theme); } catch { /* not persistable */ }
    applyThemeClass(theme);
    set({ theme });
  },
  setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
  setTimeWindow: (timeWindow) => set({ timeWindow }),
  setSearch: (search) => set({ search }),
  resetUi: () => {
    try { localStorage.removeItem(THEME_KEY); } catch { /* storage unavailable */ }
    applyThemeClass("light");
    set({ theme: "light", search: "", timeWindow: "Current run" });
  },
}));
