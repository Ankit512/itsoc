import React, { createContext, useContext, useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import {
  AuthUser,
  AuthStatus,
  AuthResponse,
  getToken,
  getMe,
  getAuthStatus,
  login as authLogin,
  signup as authSignup,
  logout as authLogout,
} from "@/lib/auth";

export interface AuthContextType {
  user: AuthUser | null;
  token: string | null;
  status: AuthStatus | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (username: string, passphrase: string) => Promise<AuthResponse>;
  signup: (
    username: string,
    passphrase: string,
    role?: "analyst" | "admin" | "viewer"
  ) => Promise<AuthResponse>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setTokenState] = useState<string | null>(() => getToken());
  const [user, setUser] = useState<AuthUser | null>(() => {
    const t = getToken();
    return t ? { username: "analyst", role: "analyst" } : null;
  });
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const checkAuth = async () => {
    try {
      const [currUser, authStatus] = await Promise.all([
        getMe(),
        getAuthStatus(),
      ]);
      setUser(currUser);
      setStatus(authStatus);
      setTokenState(getToken());
    } catch {
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  const login = async (username: string, passphrase: string): Promise<AuthResponse> => {
    const res = await authLogin(username, passphrase);
    setUser(res.user);
    setTokenState(res.token);
    setStatus((prev) => (prev ? { ...prev, hasProfile: true } : prev));
    return res;
  };

  const signup = async (
    username: string,
    passphrase: string,
    role: "analyst" | "admin" | "viewer" = "analyst"
  ): Promise<AuthResponse> => {
    const res = await authSignup(username, passphrase, role);
    setUser(res.user);
    setTokenState(res.token);
    setStatus((prev) => (prev ? { ...prev, hasProfile: true } : prev));
    return res;
  };

  const logout = async (): Promise<void> => {
    await authLogout();
    setUser(null);
    setTokenState(null);
  };

  const value: AuthContextType = {
    user,
    token,
    status,
    isLoading,
    isAuthenticated: !!user,
    login,
    signup,
    logout,
    refresh: checkAuth,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}

/**
 * Route guard component. Renders child route if authenticated,
 * or redirects to /login with return location state.
 */
export function RequireAuth({ children }: { children?: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-muted-foreground">
        <div className="flex items-center gap-2 text-[13px]">
          <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <span>Verifying local session...</span>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
