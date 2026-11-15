import React from 'react';
import { Icon } from './Icon';

/**
 * TabBar — bottom navigation with 4 playful tabs.
 * Sliding indicator + bounce on switch.
 */
const TABS = [
  { id: 'scan', label: 'Scan', icon: 'scan' },
  { id: 'stats', label: 'Stats', icon: 'stats' },
  { id: 'trusted', label: 'Trusted', icon: 'star' },
  { id: 'settings', label: 'Settings', icon: 'gear' },
];

export function TabBar({ active, onChange }) {
  const onKeyDown = (e) => {
    const i = TABS.findIndex((t) => t.id === active);
    let next = null;
    if (e.key === 'ArrowRight') next = (i + 1) % TABS.length;
    else if (e.key === 'ArrowLeft') next = (i - 1 + TABS.length) % TABS.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = TABS.length - 1;
    if (next === null) return;
    e.preventDefault();
    onChange(TABS[next].id);
    const el = e.currentTarget.querySelectorAll('[role="tab"]')[next];
    el?.focus();
  };

  return (
    <div
      role="tablist"
      aria-label="Main"
      onKeyDown={onKeyDown}
      style={{
        display: 'flex',
        background: 'var(--pn-bg-card)',
        borderTop: '1px solid var(--pn-border)',
        padding: '6px 8px',
        gap: 4,
      }}
    >
      {TABS.map((tab) => {
        const isActive = tab.id === active;
        return (
          <button
            key={tab.id}
            role="tab"
            aria-selected={isActive}
            tabIndex={isActive ? 0 : -1}
            onClick={() => onChange(tab.id)}
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 3,
              padding: '8px 4px',
              border: 'none',
              background: isActive ? 'var(--pn-coral-pale)' : 'transparent',
              borderRadius: 'var(--pn-radius-md)',
              color: isActive ? 'var(--pn-coral)' : 'var(--pn-text-tertiary)',
              fontFamily: 'var(--pn-font-body)',
              fontSize: 10,
              fontWeight: 700,
              cursor: 'pointer',
              transition: `all var(--pn-dur-fast) var(--pn-ease-spring)`,
              outline: 'none',
            }}
          >
            <Icon name={tab.icon} size={20} />
            <span>{tab.label}</span>
          </button>
        );
      })}
    </div>
  );
}
