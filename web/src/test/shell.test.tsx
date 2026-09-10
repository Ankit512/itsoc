import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { CORE_NAV, EXPERIMENTAL_NAV, NAV_GROUPS } from "@/components/layout/AppShell";
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

  it("returns to the Overview workspace when the itsoc. brand is clicked", async () => {
    const user = userEvent.setup();
    renderApp(<App />, { route: "/incidents?sel=inc-1" });
    const wordmark = await screen.findByTestId("wordmark");

    await user.click(wordmark);

    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });

  it("renders core nav items (Overview · Findings · Incidents · Sources · Settings) + Log out", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    // "Overview" also appears as the page-title heading, so allow more than one.
    for (const item of ["Overview", "Findings", "Incidents", "Sources", "Settings", "Log out"]) {
      expect(screen.getAllByText(item).length).toBeGreaterThan(0);
    }
    // Log out is an honest local action (a link to /logout), not a fake auth flow.
    expect(screen.getByText("Log out").closest("a")).toHaveAttribute("href", "/logout");
  });

  it("renders the G1 nav groups, with Overview above them as home", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");

    const main = screen.getByRole("navigation", { name: "Main" });
    for (const group of NAV_GROUPS) {
      const section = within(main).getByRole("group", { name: group.label });
      // Every item declared for a group is rendered inside THAT group, not
      // merely somewhere in the nav.
      for (const item of group.items) {
        expect(within(section).getByRole("link", { name: item.label })).toHaveAttribute("href", item.to);
      }
    }
    // Overview is a home link above the groups, not a member of one.
    const overview = within(main).getByRole("link", { name: "Overview" });
    expect(overview).toHaveAttribute("href", "/");
    for (const group of NAV_GROUPS) {
      expect(within(within(main).getByRole("group", { name: group.label })).queryByRole("link", { name: "Overview" })).toBeNull();
    }
  });

  it("keeps a plain Tab path through the whole grouped nav, in CORE_NAV order", async () => {
    const user = userEvent.setup();
    renderApp(<App />);
    await screen.findByTestId("wordmark");

    // Start from the ⌘K pill, the control immediately above the nav. Group
    // headings are plain text, so they must not consume a Tab stop: the next
    // CORE_NAV.length stops are exactly the nav links, in order.
    screen.getByRole("button", { name: /open command palette/i }).focus();
    for (const item of CORE_NAV) {
      await user.tab();
      expect(document.activeElement).toHaveAttribute("href", item.to);
      expect(document.activeElement).toHaveTextContent(item.label);
    }
    // And the stop after the last nav link is the experimental disclosure.
    await user.tab();
    expect(document.activeElement).toHaveTextContent(/Experimental/i);
  });

  it("houses Experimental as one honest disclosure row — no dead 'Command Center' box", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");

    // G1: the dashed "Command Center · off" panel is gone. It named a
    // destination App.tsx has no route for, so it could never be navigated to.
    expect(screen.queryByText(/Command Center/)).toBeNull();

    // What remains is the toggle itself, honestly reading OFF and saying how
    // many screens it is hiding.
    const expToggle = screen.getByRole("button", { name: /experimental/i });
    expect(expToggle).toHaveTextContent("OFF");
    expect(expToggle).toHaveAttribute("aria-pressed", "false");
    expect(expToggle).toHaveTextContent(String(EXPERIMENTAL_NAV.length));

    // While off, the sidebar does not advertise the experimental screens...
    const sidebar = screen.getByRole("navigation", { name: "Main" }).closest("aside")!;
    for (const { label } of EXPERIMENTAL_NAV) {
      expect(within(sidebar).queryByRole("link", { name: label })).toBeNull();
    }
    // ...but they stay REACHABLE: the command palette lists them unconditionally.
    await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
    for (const { label } of EXPERIMENTAL_NAV) {
      expect(screen.getByRole("button", { name: new RegExp(`^${label}$`, "i") })).toBeInTheDocument();
    }
    await userEvent.keyboard("{Escape}");

    // Toggle experimental on (badge reads OFF → ON, per the prototype)
    await userEvent.click(expToggle);
    expect(expToggle).toHaveTextContent("ON");
    expect(expToggle).toHaveAttribute("aria-pressed", "true");

    // Experimental items are now visible in the sidebar too
    for (const { label, to } of EXPERIMENTAL_NAV) {
      expect(within(sidebar).getByRole("link", { name: label })).toHaveAttribute("href", to);
    }

    // Turning it back off hides them again and still leaves no dead box behind.
    await userEvent.click(expToggle);
    expect(expToggle).toHaveTextContent("OFF");
    for (const { label } of EXPERIMENTAL_NAV) {
      expect(within(sidebar).queryByRole("link", { name: label })).toBeNull();
    }
    expect(screen.queryByText(/Command Center/)).toBeNull();
  });

  it("SELECTOR-NULL (shell) — the app shell carries NO approve control off /approvals", async () => {
    // The existing SELECTOR-NULL family in approvals.test.tsx / copilot-*.test.tsx
    // renders the ADVISORY surfaces and proves the approve affordance is absent
    // there. Measured during G1 by planting one: no test rendered the AppShell
    // itself, so sidebar and header chrome were outside that family's reach.
    // The shell is persistent chrome on every route, so it is exactly where a
    // stray approve control would be least noticed. Same guard, this surface.
    const { container } = renderApp(<App />, { route: "/incidents" });
    await screen.findByTestId("wordmark");
    expect(screen.queryByTestId("approval-approve")).toBeNull();
    expect(screen.queryByTestId("approval-reject")).toBeNull();
    expect(container.querySelector('[data-testid="approval-approve"]')).toBeNull();
    // And it IS the real shell, not an empty render — so this is a genuine
    // absence, not a component that failed to mount.
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(container.querySelectorAll("a[href]").length).toBeGreaterThan(0);
  });

  it("renders the top bar header actions and ⌘K trigger", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
    expect(screen.getByText("Upload logs")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /refresh/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /switch to dark mode/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /open command palette/i })).toBeInTheDocument();
  });

  it("opens the ⌘K command palette on trigger click", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
    expect(screen.getByRole("dialog", { name: "Command Palette" })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i)).toBeInTheDocument();
    const overview = screen.getByRole("button", { name: /^overview$/i });
    expect(overview).toHaveClass("is-palette__item");
    expect(overview.querySelector(".lbl")).toHaveTextContent("Overview");
    const dialog = screen.getByRole("dialog", { name: "Command Palette" });
    expect(dialog).toHaveClass("is-palette");
    expect(dialog.parentElement).toHaveClass("is-palette-overlay");
  });

  it("an unknown route renders the honest placeholder inside the same shell", async () => {
    renderApp(<App />, { route: "/no-such-page" });
    await screen.findByTestId("wordmark");
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByText(/coming in a later phase/i)).toBeInTheDocument();
    expect(screen.getByText(/rather than invented data/i)).toBeInTheDocument();
  });
});
