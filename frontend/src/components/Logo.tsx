import { useCallback, useEffect, useRef, useState } from 'react';

interface LogoProps {
  className?: string;
}

/**
 * Header logo + easter egg.
 *
 * Click the logo 5 times within 3 s of the first click and the kangal barks:
 * the static SVG is swapped for the animated barking SVG for ~2.5 s and the
 * dog bark sound plays once. The click counter is reset on completion and on
 * the inactivity timeout so it doesn't accidentally trigger on stray clicks.
 */
const CLICKS_REQUIRED = 5;
const RESET_AFTER_MS = 3000;
const BARK_DURATION_MS = 2500;

export function Logo({ className }: LogoProps) {
  const [barking, setBarking] = useState(false);
  const [clicks, setClicks] = useState(0);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const resetTimer = useRef<number | null>(null);
  const barkTimer = useRef<number | null>(null);

  // Lazily construct the audio element once (autoplay restrictions need a user
  // gesture, but the element itself can be created on mount).
  useEffect(() => {
    const a = new Audio('/kangal-bark.mp3');
    a.preload = 'auto';
    a.volume = 0.85;
    audioRef.current = a;
    return () => {
      a.pause();
      audioRef.current = null;
    };
  }, []);

  // Cancel any pending timers on unmount.
  useEffect(() => {
    return () => {
      if (resetTimer.current) window.clearTimeout(resetTimer.current);
      if (barkTimer.current) window.clearTimeout(barkTimer.current);
    };
  }, []);

  const triggerBark = useCallback(() => {
    setBarking(true);
    // Play the bark sound once. Swallow the promise rejection if the browser
    // blocks autoplay — the visual easter egg still fires.
    const a = audioRef.current;
    if (a) {
      try {
        a.currentTime = 0;
        const p = a.play();
        if (p && typeof p.catch === 'function') p.catch(() => {});
      } catch {
        /* ignore */
      }
    }
    if (barkTimer.current) window.clearTimeout(barkTimer.current);
    barkTimer.current = window.setTimeout(() => {
      setBarking(false);
    }, BARK_DURATION_MS);
  }, []);

  const handleClick = useCallback(() => {
    if (barking) return; // ignore clicks while the bark animation is playing
    setClicks((c) => {
      const next = c + 1;
      if (next >= CLICKS_REQUIRED) {
        triggerBark();
        return 0;
      }
      // Reset the inactivity window so casual clicks don't accumulate.
      if (resetTimer.current) window.clearTimeout(resetTimer.current);
      resetTimer.current = window.setTimeout(() => {
        setClicks(0);
      }, RESET_AFTER_MS);
      return next;
    });
  }, [barking, triggerBark]);

  return (
    <button
      type="button"
      onClick={handleClick}
      title="Kangal"
      aria-label="Kangal"
      className={`relative inline-flex items-center justify-center bg-transparent border-0 p-0 cursor-pointer ${
        className || ''
      }`}
      style={{ lineHeight: 0 }}
    >
      {/* Static logo (default) */}
      <img
        src="/kangal-logo.svg"
        alt="Kangal"
        className={`h-10 w-auto transition-opacity duration-150 ${
          barking ? 'opacity-0' : 'opacity-100'
        }`}
        draggable={false}
      />
      {/* Animated barking logo (easter egg) */}
      <img
        src="/kangal-barking.svg"
        alt="Kangal barking"
        className={`h-10 w-auto absolute inset-0 transition-opacity duration-150 ${
          barking ? 'opacity-100' : 'opacity-0'
        }`}
        draggable={false}
      />
      {/* Tiny click counter (only visible during multi-click, < 5 clicks). */}
      {clicks > 0 && !barking && (
        <span
          aria-hidden="true"
          className="absolute -bottom-1 -right-2 text-[9px] font-mono text-primary select-none pointer-events-none"
        >
          {clicks}
        </span>
      )}
    </button>
  );
}