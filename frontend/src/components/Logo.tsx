/**
 * The MCP Eval mark: a tall ink tile with a checked shield (the sandbox),
 * a coral tile (rejected) and a mint tile (approved). Colours come from
 * tokens so the ink tile turns light on the dark theme.
 */
export function Logo({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 64 64" role="img" aria-label="MCP Eval">
      <rect x="2" y="2" width="28" height="60" rx="9" fill="var(--logo-tile)" />
      <path
        d="M16 21.5l7 2.6v5.4c0 4.6-3 8.3-7 9.9-4-1.6-7-5.3-7-9.9v-5.4z"
        fill="none"
        stroke="var(--logo-mark)"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path d="M12.8 30.4l2.4 2.4 4.2-4.6" fill="none" stroke="var(--logo-mark)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      <rect x="34" y="2" width="28" height="28" rx="9" fill="#f0614f" />
      <rect x="34" y="34" width="28" height="28" rx="9" fill="#9fe1cb" />
      <circle cx="48" cy="48" r="3" fill="#1a1a18" />
    </svg>
  );
}
