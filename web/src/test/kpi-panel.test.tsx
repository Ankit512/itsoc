import { screen } from "@testing-library/react";
import App from "@/App";
import { OpsMetrics } from "@/components/OpsMetrics";
import { renderApp, mockFetch, consoleState, OVERVIEW } from "./helpers";

describe("C5-T4 · Operational KPI Panel (OpsMetrics)", () => {
  it("renders honest 'n/a' and 'no lifecycle basis yet' when timestamps are absent", async () => {
    mockFetch({
      "/api/metrics": {
        openIncidents: 3,
        mttaSeconds: null,
        mttaBasis: 0,
        mttrSeconds: null,
        mttrBasis: 0,
        assetsAtRisk: null,
        usersAtRisk: null,
        dataSources: 2,
      },
    });

    renderApp(<OpsMetrics />);

    // MTTA tile
    const mttaTile = await screen.findByTestId("kpi-mtta");
    expect(mttaTile).toBeInTheDocument();
    expect(mttaTile).toHaveTextContent("MTTA");
    expect(mttaTile).toHaveTextContent("n/a");
    expect(mttaTile).toHaveTextContent("no lifecycle basis yet");
    expect(mttaTile).toHaveAttribute(
      "title",
      "Mean time to acknowledge needs acknowledged incidents — no lifecycle basis yet",
    );

    // MTTR tile
    const mttrTile = screen.getByTestId("kpi-mttr");
    expect(mttrTile).toBeInTheDocument();
    expect(mttrTile).toHaveTextContent("MTTR");
    expect(mttrTile).toHaveTextContent("n/a");
    expect(mttrTile).toHaveTextContent("no lifecycle basis yet");
    expect(mttrTile).toHaveAttribute(
      "title",
      "Mean time to resolve needs resolved incidents — no lifecycle basis yet",
    );

    // Idle assets / users at risk -> honest dash + reason note
    const assetsTile = screen.getByTestId("kpi-assets-at-risk");
    expect(assetsTile).toHaveTextContent("—");
    expect(assetsTile).toHaveTextContent("no active run");

    const usersTile = screen.getByTestId("kpi-users-at-risk");
    expect(usersTile).toHaveTextContent("—");
    expect(usersTile).toHaveTextContent("no active run");

    // Open incidents & data sources
    expect(screen.getByTestId("kpi-open-incidents")).toHaveTextContent("3");
    expect(screen.getByTestId("kpi-data-sources")).toHaveTextContent("2");

    // Invariant: null must NEVER render as 0s or 0
    expect(mttaTile).not.toHaveTextContent("0s");
    expect(mttrTile).not.toHaveTextContent("0s");
  });

  it("computes and formats real durations when lifecycle basis exists", async () => {
    mockFetch({
      "/api/metrics": {
        openIncidents: 1,
        mttaSeconds: 420,
        mttaBasis: 2,
        mttrSeconds: 3720,
        mttrBasis: 1,
        assetsAtRisk: 4,
        usersAtRisk: 2,
        dataSources: 3,
      },
    });

    renderApp(<OpsMetrics />);

    // MTTA: 420s -> 7m 0s with 2 incident(s)
    const mttaTile = await screen.findByTestId("kpi-mtta");
    expect(mttaTile).toHaveTextContent("MTTA");
    expect(mttaTile).toHaveTextContent("7m 0s");
    expect(mttaTile).toHaveTextContent("2 incident(s)");
    expect(mttaTile).toHaveAttribute(
      "title",
      "Mean of created→acknowledged over 2 incident(s)",
    );

    // MTTR: 3720s -> 1h 2m with 1 incident(s)
    const mttrTile = screen.getByTestId("kpi-mttr");
    expect(mttrTile).toHaveTextContent("MTTR");
    expect(mttrTile).toHaveTextContent("1h 2m");
    expect(mttrTile).toHaveTextContent("1 incident(s)");
    expect(mttrTile).toHaveAttribute(
      "title",
      "Mean of created→resolved over 1 incident(s)",
    );

    // Active run risk counts
    expect(screen.getByTestId("kpi-assets-at-risk")).toHaveTextContent("4");
    expect(screen.getByTestId("kpi-users-at-risk")).toHaveTextContent("2");
  });

  it("does NOT publish an MTTD estimate under an unmeasured label", async () => {
    mockFetch({
      "/api/metrics": {
        openIncidents: 0,
        mttaSeconds: 60,
        mttaBasis: 1,
        mttrSeconds: 120,
        mttrBasis: 1,
        assetsAtRisk: 0,
        usersAtRisk: 0,
        dataSources: 1,
      },
    });

    renderApp(<OpsMetrics />);
    await screen.findByTestId("kpi-mtta");

    // The tile label is MTTA (Time-to-Acknowledge), NOT MTTD
    expect(screen.queryByTestId("kpi-mttd")).not.toBeInTheDocument();
    expect(screen.queryByText(/^MTTD$/)).not.toBeInTheDocument();
  });

  it("surfaces honest unavailable notice when /api/metrics fails", async () => {
    mockFetch({
      "/api/metrics": () => Promise.reject(new Error("backend down")),
    });

    renderApp(<OpsMetrics />);

    expect(
      await screen.findByText(/Operational metrics are unavailable/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Nothing is shown rather than an invented number/i),
    ).toBeInTheDocument();
    expect(screen.queryByTestId("kpi-mtta")).not.toBeInTheDocument();
  });

  it("is mounted and accessible on the Overview page", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": {
        openIncidents: 2,
        mttaSeconds: null,
        mttaBasis: 0,
        mttrSeconds: null,
        mttrBasis: 0,
        assetsAtRisk: 3,
        usersAtRisk: 1,
        dataSources: 4,
      },
      "/console_state.json": consoleState([]),
    });

    renderApp(<App />);

    expect(await screen.findByText("Operational metrics")).toBeInTheDocument();
    const mttaTile = await screen.findByTestId("kpi-mtta");
    expect(mttaTile).toHaveTextContent("n/a");
    expect(mttaTile).toHaveTextContent("no lifecycle basis yet");
  });
});
