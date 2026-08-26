import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { EXPERIMENTAL_NAV } from "@/components/layout/AppShell";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("itsoc. Phase 1 App Shell", () => {
  beforeEach(() => mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS }));

  it("renders the itsoc. wordmark with the accent dot", async () => {
    renderApp(<App />);
    // RequireAuth shows a brief "Verifying local session…" gate before the
    // shell mounts; await it so the wordmark is present.
    const wordmark = await screen.findByTestId("wordmark");
    expect(wordmark).toHaveTextContent("itsoc.");
  });

  it("renders core nav items (Overview · Findings · Incidents · Sources · Settings) + Logout", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    // "Overview" also appears as the page-title heading, so allow more than one.
    for (const item of ["Overview", "Findings", "Incidents", "Sources", "Settings", "Logout"]) {
      expect(screen.getAllByText(item).length).toBeGreaterThan(0);
    }
    // Logout is an honest local action (a link to /logout), not a fake auth flow.
    expect(screen.getByText("Logout").closest("a")).toHaveAttribute("href", "/logout");
  });

  it("houses Experimental group and toggles its visibility", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    // By default experimental is off
    expect(screen.getByText(/Command Center/)).toBeInTheDocument();
    expect(screen.getAllByText("off").length).toBeGreaterThan(0);

    // Toggle experimental on
    await userEvent.click(screen.getByRole("button", { name: /experimental/i }));
    expect(screen.getByText("on")).toBeInTheDocument();

    // Experimental items are now visible
    for (const { label } of EXPERIMENTAL_NAV) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it("renders the top bar header actions and ⌘K trigger", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByText("Upload Logs")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /refresh/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /filters/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /switch to dark mode/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /open command palette/i })).toBeInTheDocument();
  });

  it("opens the ⌘K command palette on trigger click", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
    expect(screen.getByRole("dialog", { name: "Command Palette" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i)).toBeInTheDocument();
  });

  it("an unknown route renders the honest placeholder inside the same shell", async () => {
    renderApp(<App />, { route: "/no-such-page" });
    await screen.findByTestId("wordmark");
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByText(/coming in a later phase/i)).toBeInTheDocument();
    expect(screen.getByText(/rather than invented data/i)).toBeInTheDocument();
  });
});
