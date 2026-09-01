import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import { applyThemeClass, useUi } from "@/store/ui";
import "./index.css";
// itsoc. design system (DESIGN_HANDOFF golden rule): the authoritative style
// source. Imported AFTER index.css and unlayered, so its is-* classes and
// tokens win over the Tailwind @layer base plumbing where they overlap.
import "./styles/itsoc.css";

// index.html applies the class pre-paint; re-apply from the store so React
// state and the DOM can never disagree.
applyThemeClass(useUi.getState().theme);

const queryClient = new QueryClient({
  // Keep recently visited workspace data warm during navigation. Mutations and
  // the explicit Refresh control still invalidate immediately; this avoids a
  // page feeling like it has to cold-load every time a user changes section.
  defaultOptions: { queries: { retry: 1, staleTime: 10_000, refetchOnWindowFocus: false, refetchOnReconnect: false } },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>,
);
