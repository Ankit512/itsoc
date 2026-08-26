import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { useUi } from "@/store/ui";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("Logout page (honest local demo sign out)", () => {
  beforeEach(() => mockFetch({
    "/api/overview": OVERVIEW,
    "/api/metrics": METRICS,
    "/api/auth/logout": { ok: true },
  }));

  it("states this is a local demo session and signs out", async () => {
    renderApp(<App />, { route: "/logout" });
    expect(await screen.findByRole("heading", { name: /sign out/i })).toBeInTheDocument();
    expect(screen.getByText(/local demo session/i)).toBeInTheDocument();
  });

  it("clears local UI state and local demo session on sign out", async () => {
    useUi.setState({ theme: "dark", search: "leftover" });
    renderApp(<App />, { route: "/logout" });

    await userEvent.click(await screen.findByRole("button", { name: /sign out of local session/i }));

    expect(useUi.getState().theme).toBe("light");
    expect(useUi.getState().search).toBe("");
    expect(await screen.findByText(/signed out of local demo session/i)).toBeInTheDocument();
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });
});

