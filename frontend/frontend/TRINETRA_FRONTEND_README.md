# TRINETRA Frontend Redesign

This package contains frontend changes only.

Important:
- `src/**/*.js` shadow copies were removed so Vite resolves the redesigned `.ts/.tsx` implementation.
- Backend/logic/integration files are not included in this frontend drop-in.
- The existing API services, session/polling flow, upload field, case/report rendering and routes are preserved.
- Install dependencies from `package.json`, including `@designcodeio/threeui`.

Run:
```bash
npm install
npm run dev
```

Open the Vite URL shown in the terminal. Hard-refresh the browser once after replacing an older frontend.

## V6 result dashboard

Added a security-operations-style result overview with verdict/risk summary, evidence layout, and a sender-origin world map. The map consumes only country fields already returned in `threat_intelligence.ips` / `threat_intelligence.domains`. Coordinates are country centroids in an equirectangular projection; this is intentionally country-level geolocation, not a claim of precise street location. The world map asset is the CC0/public-domain `BlankMap-World-Equirectangular.svg` from Wikimedia Commons.
