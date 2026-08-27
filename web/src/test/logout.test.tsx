import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { useUi } from "@/store/ui";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("Logout page (clears local UI state; login gate is off)", () => {
  beforeEach(() => mockFetch({
    "/api/overview": OVERVIEW,
    "/api/metrics": METRICS,
    "/api/auth/logout": { ok: true },
  }));

  it("states there is no session to end and clears local UI state", async () => {
    renderApp(<App />, { route: "/logout" });
    expect(await screen.findByRole("heading", { name: /clear this machine/i })).toBeInTheDocument();
    expect(screen.getByText(/the login gate is off, so there is no session to end/i)).toBeInTheDocument();
  });

  it("clears local UI state and local demo session on sign out", async () => {
    useUi.setState({ theme: "dark", search: "leftover" });
    renderApp(<App />, { route: "/logout" });

    await userEvent.click(await screen.findByRole("button", { name: /clear local ui state/i }));

    expect(useUi.getState().theme).toBe("light");
    expect(useUi.getState().search).toBe("");
    expect(await screen.findByText(/local ui state cleared/i)).toBeInTheDocument();
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });
});

