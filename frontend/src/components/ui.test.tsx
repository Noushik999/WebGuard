import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SeverityBadge, ScoreRing, SEV_COLORS } from './ui';

describe('SeverityBadge', () => {
  it('renders each severity with its class', () => {
    const { rerender } = render(<SeverityBadge severity="Critical" />);
    expect(screen.getByText('Critical')).toHaveClass('sev-Critical');
    rerender(<SeverityBadge severity="Low" />);
    expect(screen.getByText('Low')).toHaveClass('sev-Low');
  });
});

describe('ScoreRing', () => {
  it('renders the numeric score', () => {
    render(<ScoreRing score={82} />);
    expect(screen.getByText('82')).toBeTruthy();
    expect(screen.getByText('/ 100')).toBeTruthy();
  });
  it('renders a placeholder for missing score', () => {
    render(<ScoreRing score={null} />);
    expect(screen.getByText('—')).toBeTruthy();
  });
});

describe('SEV_COLORS', () => {
  it('covers all severities', () => {
    expect(Object.keys(SEV_COLORS).sort()).toEqual(
      ['Critical', 'High', 'Informational', 'Low', 'Medium'].sort()
    );
  });
});
