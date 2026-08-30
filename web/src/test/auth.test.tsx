import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import * as authLib from "@/lib/auth";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("Auth subsystem & login screen (Phase 6)", () => {
  beforeEach(() => {
    localStorage.clear();
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": METRICS,
      "/api/auth/status": {
        hasProfile: true,
        authType: "local_demo",
        provider: "LocalDemoAuth",
        disclaimer: "Local demo — a single profile on this machine",
      },
      "/api/auth/me": {
        user: { username: "analyst", role: "analyst", createdAt: "2026-08-26T14:00:00Z" },
      },
    });
  });

  it("renders login screen with honest local demo copy", async () => {
    mockFetch({
      "/api/auth/me": { __status: 401, error: "unauthenticated" },
    });
    renderApp(<App />, { route: "/login" });

    expect(await screen.findByText(/itsoc/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Log in" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign up" })).toBeInTheDocument();
    expect(screen.getByText(/local demo/i)).toBeInTheDocument();
    expect(screen.getByText(/quick demo:/i)).toBeInTheDocument();
  });

  it("switches between Sign In and Create Profile modes", async () => {
    mockFetch({
      "/api/auth/me": { __status: 401, error: "unauthenticated" },
    });
    renderApp(<App />, { route: "/login" });

    const createTab = await screen.findByRole("button", { name: /sign up/i });
    await userEvent.click(createTab);

    expect(screen.getByRole("button", { name: /create local profile/i })).toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
  });

  it("submits login and stores token on success", async () => {
    mockFetch({
      "/api/auth/me": { __status: 401, error: "unauthenticated" },
      "/api/auth/login": {
        user: { username: "analyst", role: "analyst" },
        token: "tok_test_12345",
      },
    });

    renderApp(<App />, { route: "/login" });

    const passInput = await screen.findByPlaceholderText("••••••••••••");
    await userEvent.type(passInput, "mypassphrase");

    const submitBtn = screen.getByRole("button", { name: /sign in to session/i });
    await userEvent.click(submitBtn);

    expect(authLib.getToken()).toBe("tok_test_12345");
  });

  it("displays honest error when login fails", async () => {
    mockFetch({
      "/api/auth/me": { __status: 401, error: "unauthenticated" },
      "/api/auth/login": {
        __status: 401,
        error: "Invalid username or passphrase",
      },
    });

    renderApp(<App />, { route: "/login" });

    const passInput = await screen.findByPlaceholderText("••••••••••••");
    await userEvent.type(passInput, "wrongpass");

    const submitBtn = screen.getByRole("button", { name: /sign in to session/i });
    await userEvent.click(submitBtn);

    expect(await screen.findByText(/invalid username or passphrase/i)).toBeInTheDocument();
  });

  // The <RequireAuth> route gate is currently off (see App.tsx — removed for
  // local demo review), so an unverifiable token no longer bounces to /login.
  // What must still hold is that the credential is DROPPED, never trusted.
  it("drops a stored token that cannot be verified", async () => {
    localStorage.setItem("itsoc_auth_token", "stale-token");
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("backend unavailable"); }));
    renderApp(<App />, { route: "/", token: "stale-token" });
    await waitFor(() => expect(authLib.getToken()).toBeNull());
  });

  // auth.ts:109 — the NON-401 error path. A 500 means the server could not
  // vouch for the token, which is not the same as vouching for it: getMe must
  // fail CLOSED and drop the credential, exactly as it does on a 401. The
  // network-throw branch is already covered by the test above; this covers the
  // "server answered, but badly" branch, which nothing else exercised.
  it("drops a stored token when the server errors (500), not just on 401", async () => {
    localStorage.setItem("itsoc_auth_token", "stale-token");
    mockFetch({
      "/api/auth/me": { __status: 500, error: "internal error" },
    });
    renderApp(<App />, { route: "/", token: "stale-token" });
    await waitFor(() => expect(authLib.getToken()).toBeNull());
  });

  it("shows already signed in banner when profile is authenticated", async () => {
    renderApp(<App />, { route: "/login" });
    expect(await screen.findByText(/already signed in/i)).toBeInTheDocument();
    expect(screen.getByText(/active profile:/i)).toBeInTheDocument();
  });
});
