import React, { useEffect, useRef, useState } from 'react';

/**
 * AnimatedNumber — counts up from 0 to target on mount.
 */
export function AnimatedNumber({ value, duration = 600 }) {
  const [display, setDisplay] = useState(0);
  const rafRef = useRef(null);
  const currentRef = useRef(0);

  useEffect(() => {
    const start = performance.now();
    // Animate from wherever the number currently sits. Starting from zero made
    // a changed target re-count from scratch (10 -> 20 flashed through 0).
    const startVal = currentRef.current;
    const target = value;
    const delta = target - startVal;
    if (delta === 0) return undefined;

    const tick = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const next = Math.round(startVal + delta * eased);
      currentRef.current = next;
      setDisplay(next);
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(tick);
      }
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, [value, duration]);

  return <>{display}</>;
}
