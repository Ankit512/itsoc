import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, Check, Compass, X } from "lucide-react";
import { useUi } from "@/store/ui";
import { TOUR_STEPS, type TourStep } from "@/lib/tour";
import { cn } from "@/lib/utils";

interface Rect { top: number; left: number; width: number; height: number; }

function getRect(selector: string): Rect | null {
  const target = document.querySelector(selector);
  if (!target) return null;
  const { top, left, width, height } = target.getBoundingClientRect();
  return { top, left, width, height };
}

/** A non-destructive, route-by-route product walkthrough. */
export function SpotlightTour() {
  const { tourOpen, stopTour } = useUi();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [stepIndex, setStepIndex] = useState(0);
  const [targetRect, setTargetRect] = useState<Rect | null>(null);

  const step: TourStep = TOUR_STEPS[stepIndex] ?? TOUR_STEPS[0];
  const isFirst = stepIndex === 0;
  const isLast = stepIndex === TOUR_STEPS.length - 1;

  useEffect(() => {
    if (!tourOpen) return;
    setStepIndex(0);
  }, [tourOpen]);

  // Update the route first. The shell stays mounted, so the current page is
  // always visible behind the tour rather than being replaced by a blank layer.
  useEffect(() => {
    if (tourOpen && pathname !== step.route) navigate(step.route);
  }, [navigate, pathname, step.route, tourOpen]);

  const updateTarget = useCallback(() => setTargetRect(getRect(step.selector)), [step.selector]);
  useLayoutEffect(() => {
    if (!tourOpen) return;
    const frame = requestAnimationFrame(updateTarget);
    window.addEventListener("resize", updateTarget);
    window.addEventListener("scroll", updateTarget, true);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", updateTarget);
      window.removeEventListener("scroll", updateTarget, true);
    };
  }, [tourOpen, pathname, updateTarget]);

  const goTo = (index: number) => setStepIndex(Math.max(0, Math.min(index, TOUR_STEPS.length - 1)));
  const next = () => isLast ? stopTour() : goTo(stepIndex + 1);

  useEffect(() => {
    if (!tourOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") stopTour();
      if (event.key === "ArrowRight") next();
      if (event.key === "ArrowLeft" && !isFirst) goTo(stepIndex - 1);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isFirst, isLast, next, stepIndex, stopTour, tourOpen]);

  if (!tourOpen) return null;

  return (
    <section className="is-tour-root" data-testid="spotlight-tour" role="dialog" aria-modal="true" aria-label="Guided tour">
      <div className="is-tour-dim" aria-hidden />
      {targetRect && (
        <div className="is-tour-spotlight" data-testid="spotlight-tour-focus" style={targetRect} aria-hidden>
          <span className="is-tour-spotlight__tag">Now viewing: {step.summary}</span>
        </div>
      )}

      <aside className="is-tour-card" data-testid="spotlight-tour-card" aria-live="polite">
        <header className="is-tour-card__head">
          <span className="is-tour-card__icon"><Compass size={16} aria-hidden /></span>
          <div>
            <p className="is-tour-card__eyebrow">Guided tour</p>
            <p className="is-tour-card__screen">{step.summary}</p>
          </div>
          <span className="is-tour-card__count">{stepIndex + 1} of {TOUR_STEPS.length}</span>
          <button className="is-tour-card__close" onClick={stopTour} aria-label="Close guided tour"><X size={16} aria-hidden /></button>
        </header>

        <div className="is-tour-progress" aria-label={`Step ${stepIndex + 1} of ${TOUR_STEPS.length}`}>
          {TOUR_STEPS.map((item, index) => (
            <button
              key={item.id}
              type="button"
              onClick={() => goTo(index)}
              className={cn("is-tour-progress__step", index === stepIndex && "active", index < stepIndex && "complete")}
              aria-label={`Go to ${item.summary}`}
              aria-current={index === stepIndex ? "step" : undefined}
            >
              {index < stepIndex ? <Check size={10} strokeWidth={3} aria-hidden /> : <span />}
            </button>
          ))}
        </div>

        <div className="is-tour-card__copy">
          <h2>{step.title}</h2>
          <p>{step.detail}</p>
        </div>
        <div className="is-tour-card__next-action"><span>Try this</span><p>{step.action}</p></div>

        <footer className="is-tour-card__actions">
          <button type="button" onClick={stopTour} className="is-tour-btn is-tour-btn--ghost">End tour</button>
          <div>
            <button type="button" onClick={() => goTo(stepIndex - 1)} disabled={isFirst} className="is-tour-btn"><ArrowLeft size={15} aria-hidden /> Back</button>
            <button type="button" onClick={next} data-testid="tour-next" className="is-tour-btn is-tour-btn--primary">
              {isLast ? "Finish tour" : <>Continue <ArrowRight size={15} aria-hidden /></>}
            </button>
          </div>
        </footer>
      </aside>
    </section>
  );
}
