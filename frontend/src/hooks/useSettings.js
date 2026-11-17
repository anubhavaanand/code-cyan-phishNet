import { useState, useEffect, useCallback, useRef } from 'react';
import { getSettings, updateSettings, onSettingsUpdate } from '@/lib/messaging';
import { DEFAULT_SETTINGS } from '@/lib/constants';

/**
 * React hook for extension settings.
 * Loads from background, listens for updates, and provides a setter
 * that persists back through chrome.runtime.
 */
export function useSettings() {
  const [settings, setSettings] = useState(DEFAULT_SETTINGS);
  const [loaded, setLoaded] = useState(false);

  // Mirror of settings for use inside callbacks without adding a dependency.
  const settingsRef = useRef(settings);
  settingsRef.current = settings;

  useEffect(() => {
    let mounted = true;

    getSettings().then((res) => {
      if (!mounted || !res) return;
      setSettings({ ...DEFAULT_SETTINGS, ...res });
      setLoaded(true);
    });

    const unsub = onSettingsUpdate((payload) => {
      if (!mounted || !payload) return;
      setSettings((prev) => ({ ...prev, ...payload }));
    });

    return () => { mounted = false; unsub(); };
  }, []);

  const update = useCallback(async (key, value) => {
    // Build from the latest state, then persist outside the updater. React may
    // call an updater more than once (StrictMode), and a network write inside it
    // would be issued twice.
    const prev = settingsRef.current;
    const next = { ...prev, [key]: value };
    setSettings(next);
    const success = await updateSettings(next);
    if (!success) {
      // Revert on failure - the write didn't persist, so restore previous state
      setSettings(prev);
    }
  }, []);

  return { settings, update, loaded };
}
