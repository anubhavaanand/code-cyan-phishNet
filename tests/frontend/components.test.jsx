import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Button, Badge, TabBar, EmptyState, Icon, LogoMark, Toast, ConfidenceRing } from '@/components';
import { AnimatedNumber } from '@/components/AnimatedNumber';

describe('Button', () => {
  it('renders its children', () => {
    render(<Button>Scan Now</Button>);
    expect(screen.getByRole('button', { name: 'Scan Now' })).toBeInTheDocument();
  });

  it('calls onClick when pressed', async () => {
    const onClick = vi.fn();
    render(<Button onClick={onClick}>Go</Button>);
    await userEvent.click(screen.getByRole('button', { name: 'Go' }));
    expect(onClick).toHaveBeenCalledTimes(1);
  });

  it('defaults to type="button" so it cannot submit a form', () => {
    render(<Button>Go</Button>);
    expect(screen.getByRole('button')).toHaveAttribute('type', 'button');
  });

  it('is disabled while loading and hides its label', () => {
    render(<Button loading>Scan Now</Button>);
    const btn = screen.getByRole('button');
    expect(btn).toBeDisabled();
    expect(screen.queryByText('Scan Now')).not.toBeInTheDocument();
  });

  it('does not fire onClick while disabled', async () => {
    const onClick = vi.fn();
    render(<Button disabled onClick={onClick}>Go</Button>);
    await userEvent.click(screen.getByRole('button', { name: 'Go' }));
    expect(onClick).not.toHaveBeenCalled();
  });

  it('honours the native disabled attribute over the prop', () => {
    render(<Button disabled>Go</Button>);
    expect(screen.getByRole('button')).toBeDisabled();
  });
});

describe('Badge', () => {
  it('renders the verdict short label and percentage', () => {
    render(<Badge label="phishing_email" confidence={0.94} />);
    expect(screen.getByText(/Phishing/)).toBeInTheDocument();
    expect(screen.getByText(/94%/)).toBeInTheDocument();
  });

  it('rounds the confidence', () => {
    render(<Badge label="legitimate_email" confidence={0.876} />);
    expect(screen.getByText(/88%/)).toBeInTheDocument();
  });

  it('treats a missing confidence as zero', () => {
    render(<Badge label="legitimate_email" />);
    expect(screen.getByText(/0%/)).toBeInTheDocument();
  });

  it('falls back to uncertain for an unknown label', () => {
    render(<Badge label="something_else" confidence={0.5} />);
    expect(screen.getByText(/Uncertain/)).toBeInTheDocument();
  });
});

describe('Toast', () => {
  it('announces itself to assistive tech', () => {
    render(<Toast message="History cleared!" />);
    const toast = screen.getByRole('status');
    expect(toast).toHaveAttribute('aria-live', 'polite');
    expect(toast).toHaveTextContent('History cleared!');
  });

  it('auto-dismisses after the duration when onDismiss is given', async () => {
    vi.useFakeTimers();
    const onDismiss = vi.fn();
    render(<Toast message="Saved" onDismiss={onDismiss} duration={1000} />);
    expect(onDismiss).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1000);
    expect(onDismiss).toHaveBeenCalledTimes(1);
    vi.useRealTimers();
  });

  it('never dismisses itself without onDismiss', () => {
    vi.useFakeTimers();
    const { rerender } = render(<Toast message="Sticky" />);
    vi.advanceTimersByTime(60000);
    expect(screen.getByRole('status')).toBeInTheDocument();
    vi.useRealTimers();
  });
});

describe('TabBar', () => {
  it('renders a tab for each section', () => {
    render(<TabBar active="scan" onChange={() => {}} />);
    expect(screen.getByRole('tablist', { name: /main/i })).toBeInTheDocument();
    for (const label of ['Scan', 'Stats', 'Trusted', 'Settings']) {
      expect(screen.getByRole('tab', { name: new RegExp(label) })).toBeInTheDocument();
    }
  });

  it('marks only the active tab as selected and focusable', () => {
    render(<TabBar active="scan" onChange={() => {}} />);
    const tabs = screen.getAllByRole('tab');
    const selected = tabs.filter((t) => t.getAttribute('aria-selected') === 'true');
    expect(selected).toHaveLength(1);
    expect(selected[0]).toHaveTextContent('Scan');
    expect(tabs.filter((t) => t.getAttribute('tabindex') === '0')).toHaveLength(1);
  });

  it('reports the selected tab id', async () => {
    const onChange = vi.fn();
    render(<TabBar active="scan" onChange={onChange} />);
    await userEvent.click(screen.getByRole('tab', { name: /Stats/ }));
    expect(onChange).toHaveBeenCalledWith('stats');
  });

  it('moves with the arrow keys', async () => {
    const onChange = vi.fn();
    render(<TabBar active="scan" onChange={onChange} />);
    const first = screen.getAllByRole('tab')[0];
    first.focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(onChange).toHaveBeenCalledWith('stats');
  });
});

describe('EmptyState', () => {
  it('renders the title and subtitle', () => {
    render(<EmptyState title="Nothing here yet" subtitle="Scan an email to begin" />);
    expect(screen.getByText('Nothing here yet')).toBeInTheDocument();
    expect(screen.getByText('Scan an email to begin')).toBeInTheDocument();
  });

  it('omits the subtitle block when not given', () => {
    render(<EmptyState title="Nothing here yet" />);
    expect(screen.getByText('Nothing here yet')).toBeInTheDocument();
  });
});

describe('Icon', () => {
  it('renders a known icon as an svg', () => {
    const { container } = render(<Icon name="scan" />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('falls back rather than rendering nothing for an unknown name', () => {
    const { container } = render(<Icon name="not_a_real_icon" />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });
});
describe('LogoMark', () => {
  it('renders an svg with a viewBox', () => {
    const { container } = render(<LogoMark />);
    const svg = container.querySelector('svg');
    expect(svg).toBeInTheDocument();
    expect(svg).toHaveAttribute('viewBox', '0 0 20 20');
  });

  it('draws both the hook and the net', () => {
    const { container } = render(<LogoMark />);
    // 12 hook runs + 25 net runs
    expect(container.querySelectorAll('rect')).toHaveLength(37);
  });

  it('uses currentColor for a mono mark so it inherits the tile colour', () => {
    const { container } = render(<LogoMark mono />);
    const fills = [...container.querySelectorAll('rect')].map((r) => r.getAttribute('fill'));
    expect(new Set(fills)).toEqual(new Set(['currentColor']));
  });

  it('colours the hook and net separately in the default variant', () => {
    const { container } = render(<LogoMark />);
    const fills = new Set([...container.querySelectorAll('rect')].map((r) => r.getAttribute('fill')));
    expect(fills.size).toBe(2);
  });

  it('animates by default and can be stilled', () => {
    const { container, rerender } = render(<LogoMark />);
    expect(container.querySelector('g[style*="pn-logo-lift"]')).toBeInTheDocument();

    rerender(<LogoMark animated={false} />);
    expect(container.querySelector('g[style*="pn-logo-lift"]')).not.toBeInTheDocument();
  });

  it('is hidden from assistive tech unless given a title', () => {
    const { container, rerender } = render(<LogoMark />);
    expect(container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');

    rerender(<LogoMark title="PhishNet" />);
    const svg = container.querySelector('svg');
    expect(svg).toHaveAttribute('role', 'img');
    expect(svg).toHaveAttribute('aria-label', 'PhishNet');
  });
});

describe('ConfidenceRing', () => {
  it('renders the percentage as text', () => {
    render(<ConfidenceRing value={0.87} />);
    expect(screen.getByText('87%')).toBeInTheDocument();
  });

  it('starts empty and then fills, so the transition has a start value', () => {
    const { container } = render(<ConfidenceRing value={0.5} size={56} stroke={5} />);
    const ring = container.querySelectorAll('circle')[1];
    const circumference = 2 * Math.PI * ((56 - 5) / 2);
    expect(Number(ring.getAttribute('stroke-dashoffset'))).toBeCloseTo(circumference, 1);
  });

  test('settles on the target offset after the frame', async () => {
    const { container } = render(<ConfidenceRing value={0.5} size={56} stroke={5} />);
    const ring = container.querySelectorAll('circle')[1];
    const circumference = 2 * Math.PI * ((56 - 5) / 2);
    await waitFor(() => {
      expect(Number(ring.getAttribute('stroke-dashoffset'))).toBeCloseTo(circumference / 2, 1);
    });
  });

  test('drains back to empty when the value resets to zero', async () => {
    const { container, rerender } = render(<ConfidenceRing value={0.9} />);
    const ring = container.querySelectorAll('circle')[1];
    const circumference = 2 * Math.PI * ((56 - 5) / 2);
    await waitFor(() => {
      expect(Number(ring.getAttribute('stroke-dashoffset'))).toBeLessThan(circumference);
    });
    rerender(<ConfidenceRing value={0} />);
    await waitFor(() => {
      expect(Number(ring.getAttribute('stroke-dashoffset'))).toBeCloseTo(circumference, 1);
    });
  });
});

describe('AnimatedNumber', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('counts up from zero on first mount', () => {
    const { container } = render(<AnimatedNumber value={10} duration={100} />);
    expect(container.textContent).toBe('0');
  });

  test('settles exactly on the target', async () => {
    const { container } = render(<AnimatedNumber value={10} duration={100} />);
    await vi.advanceTimersByTimeAsync(200);
    expect(Number(container.textContent)).toBe(10);
  });

  test('a changed target never renders below the value it started from', async () => {
    const { container, rerender } = render(<AnimatedNumber value={10} duration={100} />);
    await vi.advanceTimersByTimeAsync(200);
    expect(Number(container.textContent)).toBe(10);

    rerender(<AnimatedNumber value={20} duration={100} />);
    const seen = [];
    for (let i = 0; i < 8; i += 1) {
      await vi.advanceTimersByTimeAsync(10);
      seen.push(Number(container.textContent));
    }
    for (const v of seen) {
      expect(v).toBeGreaterThanOrEqual(10);
      expect(v).toBeLessThanOrEqual(20);
    }
    await vi.advanceTimersByTimeAsync(200);
    expect(Number(container.textContent)).toBe(20);
  });
});
