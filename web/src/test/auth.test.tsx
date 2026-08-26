import { screen } from "@testing-library/react";
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

    expect(await screen.findByRole("heading", { name: /itsoc/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign In" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create Profile" })).toBeInTheDocument();
    expect(screen.getByText(/local demo/i)).toBeInTheDocument();
    expect(screen.getByText(/quick demo:/i)).toBeInTheDocument();
  });

  it("switches between Sign In and Create Profile modes", async () => {
    mockFetch({
      "/api/auth/me": { __status: 401, error: "unauthenticated" },
    });
    renderApp(<App />, { route: "/login" });

    const createTab = await screen.findByRole("button", { name: /create profile/i });
    await userEvent.click(createTab);

    expect(screen.getByRole("button", { name: /create local profile/i })).toBeInTheDocument();
    expect(screen.getByRole("combobox")).toBeInTheDocument(); // Role select
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

  it("shows already signed in banner when profile is authenticated", async () => {
    renderApp(<App />, { route: "/login" });
    expect(await screen.findByText(/already signed in/i)).toBeInTheDocument();
    expect(screen.getByText(/active profile:/i)).toBeInTheDocument();
  });
});
