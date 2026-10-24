Vendored front-end assets (no npm, no CDN at runtime; CSP is script-src 'self').

htmx.min.js
  Download a 2.x release from https://github.com/bigskysoftware/htmx/releases,
  check it against the release's published hash, then record yours:
    sha256sum htmx.min.js >> SHA256SUMS
  The app works without it (plain links, full page loads); only the
  "Run full update" / "Rescore" buttons need it.

JetBrainsMono-Regular.woff2, JetBrainsMono-Bold.woff2
  From https://github.com/JetBrains/JetBrainsMono/releases (OFL-1.1).
  Without them the CSS falls back to ui-monospace.
