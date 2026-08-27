/**
 * web/src/lib/auth.ts — Single client swap-seam module for authentication.
 *
 * SPEC §5 / Phase 6:
 * All auth calls go through this module. Today it talks to the local demo
 * single-profile backend stub (/api/auth/*). In the future, swapping to real
 * token/passkey/OIDC identity requires changes ONLY in this file — no UI rewrites.
 */

export interface AuthUser {
  username: string;
  role: "analyst" | "admin" | "viewer";
  createdAt?: string;
}

export interface AuthResponse {
  user: AuthUser;
  token: string;
  authenticated?: boolean;
  error?: string;
}

export interface AuthStatus {
  hasProfile: boolean;
  authType: string;
  provider: string;
  principle?: string;
  disclaimer?: string;
  activeUsername?: string | null;
}

export const AUTH_STORAGE_KEY = "itsoc_auth_token";

export function getToken(): string | null {
  try {
    return localStorage.getItem(AUTH_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setToken(token: string): void {
  try {
    localStorage.setItem(AUTH_STORAGE_KEY, token);
  } catch {
    // ignore storage quota / disabled storage
  }
}

export function clearToken(): void {
  try {
    localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // ignore
  }
}

export function authHeaders(): Record<string, string> {
  const token = getToken();
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

/** Get status of the auth backend provider. */
export async function getAuthStatus(): Promise<AuthStatus> {
  try {
    const res = await fetch("/api/auth/status", {
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      return {
        hasProfile: false,
        authType: "local_demo",
        provider: "LocalDemoAuth",
        disclaimer: "Local demo session",
      };
    }
    return (await res.json()) as AuthStatus;
  } catch {
    return {
      hasProfile: false,
      authType: "local_demo",
      provider: "LocalDemoAuth",
      disclaimer: "Local demo session",
    };
  }
}

/** Retrieve the current profile.
 *
 *  Called even with no stored token: when the owner has switched the login gate
 *  off (serve.py AUTH_REQUIRED), /api/auth/me answers 200 with the machine's
 *  local profile and `authenticated: false, authDisabled: true`. We surface
 *  that user so the shell can name the operator, while `isAuthenticated` stays
 *  false — the UI must never imply a login happened. With the gate on and no
 *  token the endpoint is still 401 and this returns null, as before. */
export async function getMe(): Promise<AuthUser | null> {
  try {
    const res = await fetch("/api/auth/me", {
      headers: authHeaders(),
    });
    if (!res.ok) {
      if (res.status === 401) {
        clearToken();
        return null;
      }
      clearToken();
      return null;
    }
    const data = (await res.json()) as { user: AuthUser | null };
    return data.user ?? null;
  } catch {
    clearToken();
    return null;
  }
}

/** Authenticate with username and passphrase. */
export async function login(username: string, passphrase: string): Promise<AuthResponse> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, passphrase }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Login failed (${res.status})`);
  }
  if (data.token) {
    setToken(data.token);
  }
  return data as AuthResponse;
}

/** Create or reset the local profile. */
export async function signup(
  username: string,
  passphrase: string,
  role: "analyst" | "admin" | "viewer" = "analyst"
): Promise<AuthResponse> {
  const res = await fetch("/api/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, passphrase, role }),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Signup failed (${res.status})`);
  }
  if (data.token) {
    setToken(data.token);
  }
  return data as AuthResponse;
}

/** Sign out and invalidate session. */
export async function logout(): Promise<void> {
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      headers: authHeaders(),
    });
  } catch {
    // ignore network errors on logout
  } finally {
    clearToken();
  }
}
