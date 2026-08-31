import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { api } from "@/lib/api";
import { useUi } from "@/store/ui";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

/** Separate "Ask AI" helper bot (distinct from the run analyst rail): greeting,
 *  help + navigation quick actions, advisory chat, and a tour tie-in. */
describe("Ask AI helper bot", () => {
  beforeEach(() => {
    useUi.setState({ tourOpen: false, tourPage: undefined });
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS });
  });

  it("opens from the FAB with a greeting, help actions, nav shortcuts, and an advisory footer", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    await userEvent.click(screen.getByTestId("askai-fab"));

    const panel = screen.getByTestId("askai-panel");
    expect(panel).toBeInTheDocument();
    expect(screen.getByTestId("askai-greeting")).toHaveTextContent(/what can i help you with/i);
    expect(screen.getByTestId("askai-help-actions")).toHaveTextContent(/take the guided tour/i);
    expect(screen.getByTestId("askai-nav-actions")).toHaveTextContent(/overview/i);
    expect(screen.getByTestId("askai-advisory-chip")).toHaveTextContent(/advisory/i);
    expect(screen.getByTestId("askai-footer")).toHaveTextContent(/rules set severity/i);
  });

  it("'Take the guided tour' launches the SpotlightTour", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    await userEvent.click(screen.getByTestId("askai-fab"));
    await userEvent.click(screen.getByTestId("askai-action-tour"));

    expect(await screen.findByTestId("spotlight-tour-card")).toBeInTheDocument();
    expect(screen.getByTestId("spotlight-tour-card")).toHaveTextContent(/start at overview/i);
  });

  it("streams a free-text answer through the typewriter and shows it", async () => {
    vi.spyOn(api, "askStream").mockImplementation(async (_q, onDelta) => {
      onDelta("Click Findings in the sidebar to review what the rules caught.");
    });
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    await userEvent.click(screen.getByTestId("askai-fab"));

    const box = screen.getByLabelText("Ask the AI assistant a question");
    await userEvent.type(box, "how do I review findings?");
    await userEvent.click(screen.getByRole("button", { name: "Send" }));

    expect(await screen.findByText(/click findings in the sidebar/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(document.querySelector('[data-testid="askai-typewriter"]')?.textContent)
        .toBe("Click Findings in the sidebar to review what the rules caught.");
    });
  });
});
