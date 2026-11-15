import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { installChrome } from './helpers/chrome.js';

/**
 * Hook tests. Each hook is a thin wrapper over the messaging layer, so these
 * assert the wiring: what is requested on mount, how the response is applied,
 * and that subscriptions are torn down.
 */

const mock = installChrome();

const loadHook = async (name) => {
  vi.resetModules();
  const mod = await import(`@/hooks/${name}.js`);
  return mod[name];
};

describe('useSettings', () => {
  beforeEach(() => {
    mock.reset();
    mock.respondWith({
      autoScan: true,
      sensitivityThreshold: 0.7,
      highlightLinks: true,
      showTooltip: true,
      theme: 'auto',
      whitelist: [],
    });
  });

  it('loads settings on mount and reports loaded', async () => {
    const useSettings = await loadHook('useSettings');
    const { result } = renderHook(() => useSettings());

    await waitFor(() => expect(result.current.loaded).toBe(true));
    expect(result.current.settings.theme).toBe('auto');
  });

  it('applies a pushed settings update', async () => {
    const useSettings = await loadHook('useSettings');
    const { result } = renderHook(() => useSettings());
    await waitFor(() => expect(result.current.loaded).toBe(true));

    act(() => {
      mock.deliver({ type: 'SETTINGS_UPDATE', payload: { theme: 'dark' } });
    });

    expect(result.current.settings.theme).toBe('dark');
    // untouched keys survive a partial push
    expect(result.current.settings.autoScan).toBe(true);
  });

  it('update() writes through to the worker', async () => {
    const useSettings = await loadHook('useSettings');
    const { result } = renderHook(() => useSettings());
    await waitFor(() => expect(result.current.loaded).toBe(true));

    await act(async () => {
      await result.current.update('theme', 'dark');
    });

    const call = mock.sent.find((m) => m.type === 'UPDATE_SETTINGS');
    expect(call).toBeDefined();
    expect(call.settings.theme).toBe('dark');
  });

  it('update() persists exactly once per call', async () => {
    const useSettings = await loadHook('useSettings');
    const { result } = renderHook(() => useSettings());
    await waitFor(() => expect(result.current.loaded).toBe(true));

    await act(async () => {
      await result.current.update('theme', 'dark');
    });

    // The write used to live inside the setSettings updater, which React can
    // invoke twice; one call must mean one write.
    const writes = mock.sent.filter((m) => m.type === 'UPDATE_SETTINGS');
    expect(writes).toHaveLength(1);
  });

  it('update() merges onto the latest settings, not a stale snapshot', async () => {
    const useSettings = await loadHook('useSettings');
    const { result } = renderHook(() => useSettings());
    await waitFor(() => expect(result.current.loaded).toBe(true));

    await act(async () => {
      await result.current.update('theme', 'dark');
    });
    await act(async () => {
      await result.current.update('highlightLinks', false);
    });

    const writes = mock.sent.filter((m) => m.type === 'UPDATE_SETTINGS');
    const last = writes[writes.length - 1];
    expect(last.settings.theme).toBe('dark');
    expect(last.settings.highlightLinks).toBe(false);
  });
});

describe('useModelStatus', () => {
  beforeEach(() => {
    mock.reset();
    vi.useFakeTimers();
  });

  it('starts in loading and picks up the polled status', async () => {
    mock.respondWith({ modelStatus: 'ready', progress: 1 });
    const useModelStatus = await loadHook('useModelStatus');
    const { result } = renderHook(() => useModelStatus(1000));

    expect(result.current.status).toBe('loading');

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    expect(result.current.status).toBe('ready');
    expect(result.current.progress).toBe(1);
  });

  it('applies a pushed status update', async () => {
    mock.respondWith({ modelStatus: 'loading', progress: 0 });
    const useModelStatus = await loadHook('useModelStatus');
    const { result } = renderHook(() => useModelStatus(1000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });

    act(() => {
      mock.deliver({ type: 'MODEL_STATUS', payload: { status: 'ready', progress: 1 } });
    });

    expect(result.current.status).toBe('ready');

    vi.useRealTimers();
  });

  it('clears a stale error once the status recovers', async () => {
    mock.respondWith({ modelStatus: 'error', progress: 0, error: 'Model failed to load' });
    const useModelStatus = await loadHook('useModelStatus');
    const { result } = renderHook(() => useModelStatus(1000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.error).toBe('Model failed to load');

    mock.respondWith({ modelStatus: 'ready', progress: 1 });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(result.current.status).toBe('ready');
    expect(result.current.error).toBeNull();

    vi.useRealTimers();
  });

  it('clears a stale error on a pushed recovery', async () => {
    mock.respondWith({ modelStatus: 'error', progress: 0, error: 'Nope' });
    const useModelStatus = await loadHook('useModelStatus');
    const { result } = renderHook(() => useModelStatus(1000));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(result.current.error).toBe('Nope');

    act(() => {
      mock.deliver({ type: 'MODEL_STATUS', payload: { status: 'ready', progress: 1 } });
    });
    expect(result.current.error).toBeNull();

    vi.useRealTimers();
  });

  it('clears its polling interval on unmount', async () => {
    mock.respondWith({ modelStatus: 'ready', progress: 1 });
    const useModelStatus = await loadHook('useModelStatus');
    const { unmount } = renderHook(() => useModelStatus(1000));

    const before = mock.sent.length;
    unmount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10000);
    });

    expect(mock.sent.length).toBe(before);

    vi.useRealTimers();
  });
});

describe('useScanHistory', () => {
  beforeEach(() => {
    mock.reset();
  });

  it('loads history from storage on mount', async () => {
    mock.setLocal('scanHistory', [{ id: 1, label: 'phishing_email', confidence: 90 }]);
    const useScanHistory = await loadHook('useScanHistory');
    const { result } = renderHook(() => useScanHistory());

    await waitFor(() => expect(result.current.history).toHaveLength(1));
    expect(result.current.history[0].label).toBe('phishing_email');
  });

  it('defaults to empty history when storage is empty', async () => {
    const useScanHistory = await loadHook('useScanHistory');
    const { result } = renderHook(() => useScanHistory());

    await waitFor(() => expect(result.current.history).toEqual([]));
  });

  it('clear() empties the history and calls CLEAR_HISTORY', async () => {
    mock.setLocal('scanHistory', [{ id: 1 }]);
    const useScanHistory = await loadHook('useScanHistory');
    const { result } = renderHook(() => useScanHistory());
    await waitFor(() => expect(result.current.history).toHaveLength(1));

    await act(async () => {
      await result.current.clear();
    });

    expect(result.current.history).toEqual([]);
    expect(mock.sent.some((m) => m.type === 'CLEAR_HISTORY')).toBe(true);
  });
});