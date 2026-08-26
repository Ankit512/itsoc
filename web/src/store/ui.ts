import { create } from "zustand";

/** UI-only state. Server state lives in TanStack Query; nothing here decides
 *  anything about findings or severity. */

export type Theme = "light" | "dark";
const THEME_KEY = "itsoc-theme";

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
  // Two consumers, one source: the `dark` class drives tailwind
  // (darkMode:"class"); `data-theme` is the design-token contract from the
  // redesign spec §2 ([data-theme=light] override in index.css). Always
  // stamped together so they can never disagree.
  document.documentElement.classList.toggle("dark", theme === "dark");
  document.documentElement.setAttribute("data-theme", theme);
}

interface UiState {
  theme: Theme;
  sidebarOpen: boolean;
  timeWindow: string;
  search: string;
  commandPaletteOpen: boolean;
  experimentalEnabled: boolean;
  toggleTheme: () => void;
  setSidebarOpen: (open: boolean) => void;
  setTimeWindow: (w: string) => void;
  setSearch: (s: string) => void;
  setCommandPaletteOpen: (open: boolean) => void;
  toggleCommandPalette: () => void;
  toggleExperimental: () => void;
  /** Clear local UI state to a neutral default — used by the honest Logout,
   *  which has no server session to end. Forgets the saved theme too. */
  resetUi: () => void;
}

export const useUi = create<UiState>((set, get) => ({
  theme: readInitialTheme(),
  sidebarOpen: true,
  timeWindow: "Current run",
  search: "",
  commandPaletteOpen: false,
  experimentalEnabled: false,
  toggleTheme: () => {
    const theme: Theme = get().theme === "dark" ? "light" : "dark";
    try { localStorage.setItem(THEME_KEY, theme); } catch { /* not persistable */ }
    applyThemeClass(theme);
    set({ theme });
  },
  setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
  setTimeWindow: (timeWindow) => set({ timeWindow }),
  setSearch: (search) => set({ search }),
  setCommandPaletteOpen: (commandPaletteOpen) => set({ commandPaletteOpen }),
  toggleCommandPalette: () => set((s) => ({ commandPaletteOpen: !s.commandPaletteOpen })),
  toggleExperimental: () => set((s) => ({ experimentalEnabled: !s.experimentalEnabled })),
  resetUi: () => {
    try { localStorage.removeItem(THEME_KEY); } catch { /* storage unavailable */ }
    applyThemeClass("light");
    set({ theme: "light", search: "", timeWindow: "Current run", commandPaletteOpen: false, experimentalEnabled: false });
  },
}));
