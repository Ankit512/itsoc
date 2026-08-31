import { useCallback, useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, BookOpen, X } from "lucide-react";
import { useUi } from "@/store/ui";
import { TOUR_STEPS, type TourStep } from "@/lib/tour";
import { cn } from "@/lib/utils";

/** Fallback when a spotlight target isn't found — center the card instead of
 *  pretending to highlight something that doesn't exist (honest surface). */
const CENTERED_FALLBACK = true;

interface Rect {
  top: number; left: number; width: number; height: number;
}

/** Wait for a selector to appear in the DOM (route renders async), with a
 *  bounded retry so we never hang on a step whose target was removed. */
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

  // Reset the tour when it opens. Always begin at step 1 (Overview) so a
  // first-time walkthrough is predictable — never jumps to wherever you are.
  useEffect(() => {
    setStepIdx(0);
    setTargetFound(false);
    setRect(null);
  }, [tourOpen]);

  const step: TourStep = TOUR_STEPS[Math.min(stepIdx, TOUR_STEPS.length - 1)];

  // Navigate + spotlight on each step change.
  useEffect(() => {
    if (!tourOpen) return;
    if (step.route !== pathname) {
      navigate(step.route);
    }
    let alive = true;
    waitForSelector(step.selector).then((el) => {
      if (!alive) return;
      if (el) {
        const r = el.getBoundingClientRect();
        setTargetFound(true);
        setRect({ top: r.top, left: r.left, width: r.width, height: r.height });
      } else {
        setTargetFound(false);
        setRect(null);
      }
    });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tourOpen, stepIdx, step.route]);

  // Recompute on scroll/resize so the spotlight tracks the element.
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
      {/* Light scrim so the page stays readable while the target is ringed */}
      <div className="is-tour-backdrop" onClick={stopTour} aria-hidden />
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

      {/* Step card */}
      <div
        className={cn("is-tour-card", !targetFound && CENTERED_FALLBACK && "is-tour-card--center")}
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
        <h3 className="is-tour-card__title">{step.title}</h3>
        <p className="is-tour-card__body">{step.body}</p>
        <div className="is-tour-card__actions">
          <button onClick={stopTour} className="is-tour-btn is-tour-btn--ghost">Skip</button>
          <div className="ml-auto flex items-center gap-1.5">
            <button
              onClick={goPrev}
              disabled={isFirst}
              className="is-tour-btn"
              aria-label="Previous step"
            >
              <ArrowLeft className="h-3.5 w-3.5" aria-hidden />
            </button>
            <button
              onClick={goNext}
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
