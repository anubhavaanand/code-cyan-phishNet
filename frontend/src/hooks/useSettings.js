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
    // Sequence number incremented by every SETTINGS_UPDATE. If an update
    // arrives while getSettings() is in flight, the getSettings() snapshot is
    // stale and must not clobber the newer pushed state (issue #362).
    let updateSeq = 0;

    const fetchAndApply = async () => {
      const seqAtStart = updateSeq;
      const res = await getSettings();
      if (!mounted || !res) return;
      // Only apply the snapshot if no newer update landed while we waited.
      if (seqAtStart !== updateSeq) return;
      setSettings({ ...DEFAULT_SETTINGS, ...res });
      setLoaded(true);
    };
    fetchAndApply();

    const unsub = onSettingsUpdate((payload) => {
      if (!mounted || !payload) return;
      updateSeq += 1;
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
    const result = await updateSettings(next);
    // updateSettings() returns { success: false, error } on validation failure
    // (truthy object) or null on transport failure. Both mean the write failed.
    if (!result || result.success === false) {
      // Revert on failure - the write didn't persist, so restore previous state
      setSettings(prev);
    }
  }, []);

  return { settings, update, loaded };
}
