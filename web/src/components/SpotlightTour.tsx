import { useCallback, useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, BookOpen, X } from "lucide-react";
import { useUi } from "@/store/ui";
import { TOUR_STEPS, type TourStep } from "@/lib/tour";
import { cn } from "@/lib/utils";

/** No fallback needed — sidebar nav links are always present. */

interface Rect {
  top: number; left: number; width: number; height: number;
}

/** Wait for a selector to appear in the DOM with a bounded retry. */
function waitForSelector(selector: string, timeoutMs = 2500): Promise<Element | null> {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      const el = document.querySelector(selector);
      if (el) return resolve(el);
      if (Date.now() >= deadline) return resolve(null);
      requestAnimationFrame(tick);
    };
    tick();
  });
}

export function SpotlightTour() {
  const { tourOpen, stopTour } = useUi();
  const navigate = useNavigate();
  const { pathname } = useLocation();

  const [stepIdx, setStepIdx] = useState(0);
  const [rect, setRect] = useState<Rect | null>(null);
  const [targetFound, setTargetFound] = useState(false);
  const [navigating, setNavigating] = useState(false);

  // Reset the tour when it opens. Always begin at step 1 (Overview).
  useEffect(() => {
    if (!tourOpen) return;
    setStepIdx(0);
    setTargetFound(false);
    setRect(null);
  }, [tourOpen]);

  const step: TourStep = TOUR_STEPS[Math.min(stepIdx, TOUR_STEPS.length - 1)];

  // Navigate to the step's route, then find the sidebar nav link and ring it.
  useEffect(() => {
    if (!tourOpen) return;

    const go = async () => {
      setNavigating(true);
      if (step.route !== pathname) {
        navigate(step.route);
        // Give the route a moment to render before we look for the selector.
        await new Promise((r) => setTimeout(r, 120));
      }
      let alive = true;
      const el = await waitForSelector(step.selector);
      if (!alive) return;
      if (el) {
        const r = el.getBoundingClientRect();
        setTargetFound(true);
        setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
      } else {
        setTargetFound(false);
        setRect(null);
      }
      setNavigating(false);
    };
    go();
    return () => { /* alive flag handled by waitForSelector */ };
  }, [tourOpen, stepIdx, step.route, pathname, navigate]);

  // Recompute on scroll/resize so the ring tracks the element.
  const recompute = useCallback(() => {
    if (!tourOpen || !step) return;
    const el = document.querySelector(step.selector);
    if (el) {
      const r = el.getBoundingClientRect();
      setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
    }
  }, [tourOpen, step]);
  useEffect(() => {
    if (!tourOpen) return;
    window.addEventListener("scroll", recompute, true);
    window.addEventListener("resize", recompute);
    return () => {
      window.removeEventListener("scroll", recompute, true);
      window.removeEventListener("resize", recompute);
    };
  }, [tourOpen, recompute]);

  if (!tourOpen) return null;

  const isLast = stepIdx === TOUR_STEPS.length - 1;
  const isFirst = stepIdx === 0;

  const goNext = () => {
    if (isLast) return stopTour();
    setStepIdx((i) => i + 1);
  };
  const goPrev = () => setStepIdx((i) => Math.max(0, i - 1));

  return (
    <div data-testid="spotlight-tour" className="itsoc is-tour-root" role="dialog" aria-modal="true" aria-label="Guided tour">
      {/* No scrim — the page stays fully visible. Only the accent ring marks the target. */}
      {targetFound && rect && (
        <div
          className="is-tour-spotlight"
          style={{ top: rect.top, left: rect.left, width: rect.width, height: rect.height }}
          data-testid="spotlight-tour-focus"
          aria-hidden
        >
          <span className="is-tour-spotlight__tag">Highlighted — {step.title}</span>
        </div>
      )}

      {/* Step card at bottom center */}
      <div
        className="is-tour-card"
        data-testid="spotlight-tour-card"
      >
        <div className="is-tour-card__head">
          <BookOpen className="h-4 w-4 text-primary" aria-hidden />
          <span className="font-semibold">Guided tour</span>
          <span className="is-tour-card__count">{stepIdx + 1} / {TOUR_STEPS.length}</span>
          <button
            className="is-tour-card__close"
            onClick={stopTour}
            aria-label="End tour"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>
        {navigating && <div className="is-tour-card__nav">Loading {step.title}…</div>}
        <h3 className="is-tour-card__title">{step.title}</h3>
        <p className="is-tour-card__body">{step.body}</p>
        <div className="is-tour-card__actions">
          <button onClick={stopTour} className="is-tour-btn is-tour-btn--ghost">Skip</button>
          <div className="ml-auto flex items-center gap-1.5">
            <button
              onClick={goPrev}
              disabled={isFirst || navigating}
              className="is-tour-btn"
              aria-label="Previous step"
            >
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
            </button>
            <button
              onClick={goNext}
              disabled={navigating}
              data-testid="tour-next"
              className={cn("is-tour-btn", isLast && "is-tour-btn--primary")}
            >
              {isLast ? "Done" : <>Next <ArrowRight className="h-3.5 w-3.5" aria-hidden /></>}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}