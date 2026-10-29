# Dashboard assets

The Python dashboard serves the committed files in `web/assets/`. Running it needs Python and `requirements.txt`; Node is a development dependency for rebuilding the browser assets.

From the repository root, rebuild with Node 22 or later:

```sh
npm ci
npm run build:web
node tools/build-web.mjs --check
```

`package-lock.json` pins React 18, esbuild, Tailwind CSS and the Fontsource font packages. The build compiles `web/src/app.jsx`, bundles React, generates the Tailwind utilities used by the source, and copies fonts and licenses into `web/assets/`. `web/command.css` holds the custom visual styles. The HTML shell loads those local files; it does not need a browser JSX compiler or a CDN.

The build uses an isolated temporary directory and replaces the shipped asset directory after compilation succeeds. `--check` rebuilds separately, compares file names and SHA-256 hashes with `web/assets/manifest.json`, and checks the actual committed bytes. Run a normal build after changing JSX, Tailwind configuration or font imports. Commit the source, generated assets and manifest together.

React is distributed under the MIT license. Manrope and Barlow Condensed use the SIL Open Font License; IBM Plex Mono uses the SIL Open Font License. The full notices shipped by the pinned packages are copied to `web/assets/licenses/`. React DOM shares the React project's MIT license.

The application release is defined in `qshield_version.py`; scan metadata, health responses and CBOM tool metadata use it. The dashboard displays the version in its scan response. Keep the development package/asset manifest version aligned when cutting a release; the Python asset regression checks that parity. Engine, ruleset, source evidence and CycloneDX schema versions have separate meanings and are not the application release.

External primary-source links in the incident brief are optional navigation. The dashboard must render, scan local repositories and export stored results with external subresource requests blocked. TLS scans still require network access to their explicitly selected endpoint. Browser verification belongs alongside the Python regression suite and the asset rebuild check; a successful compile alone does not verify interaction or layout.
