import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { useUi } from "@/store/ui";
import { TOUR_STEPS } from "@/lib/tour";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("Guided Tour (SpotlightTour)", () => {
  beforeEach(() => {
    useUi.setState({ tourOpen: false, tourPage: undefined });
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS });
  });

  it("exposes 'Start guided tour' as a command palette action", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    await userEvent.click(screen.getByRole("button", { name: /open command palette/i }));
    const input = screen.getByPlaceholderText(/search screens, actions, or ask itsoc/i);
    await userEvent.type(input, "guided tour");
    expect(screen.getByRole("button", { name: /start guided tour/i })).toBeInTheDocument();
  });

  it("launches the tour and walks the steps with Next/Skip/Done", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    useUi.getState().startTour();

    const card = await screen.findByTestId("spotlight-tour-card");
    expect(card).toBeInTheDocument();
    // First step is Overview
    expect(card).toHaveTextContent(TOUR_STEPS[0].title);

    // Next advances the step counter
    await userEvent.click(screen.getByTestId("tour-next"));
    expect(card).toHaveTextContent(TOUR_STEPS[1].title);
    expect(card).toHaveTextContent(`2 / ${TOUR_STEPS.length}`);

    // Skip ends the tour
    await userEvent.click(screen.getByRole("button", { name: "Skip" }));
    await waitFor(() => expect(screen.queryByTestId("spotlight-tour")).not.toBeInTheDocument());
  });

  it("Done on the last step closes the tour", async () => {
    renderApp(<App />);
    await screen.findByTestId("wordmark");
    useUi.getState().startTour();

    const card = await screen.findByTestId("spotlight-tour-card");
    // Jump straight to the last step
    useUi.setState({ tourOpen: true });
    for (let i = 0; i < TOUR_STEPS.length - 1; i++) {
      await userEvent.click(screen.getByTestId("tour-next"));
    }
    expect(card).toHaveTextContent(TOUR_STEPS[TOUR_STEPS.length - 1].title);
    await userEvent.click(screen.getByRole("button", { name: /done/i }));
    await waitFor(() => expect(screen.queryByTestId("spotlight-tour")).not.toBeInTheDocument());
  });
});
