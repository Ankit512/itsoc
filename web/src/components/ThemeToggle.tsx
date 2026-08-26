import { Moon, Sun } from "lucide-react";
import { useUi } from "@/store/ui";

/** Flips `data-theme` (+ the `dark` class) on <html>; the choice is persisted,
 *  and index.html applies it pre-paint on the next visit. is-btn styled. */
export function ThemeToggle() {
  const theme = useUi((s) => s.theme);
  const toggleTheme = useUi((s) => s.toggleTheme);
  const dark = theme === "dark";
  return (
    <button
      className="is-btn"
      onClick={toggleTheme}
      aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
      title="Theme is saved for your next visit"
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      {dark ? "Light" : "Dark"}
    </button>
  );
}
