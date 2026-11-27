# NEXUS incident dashboard

Start the fixture API from the repository root with the Python tools environment: `python tools/mock_server.py --port 8000 --token devtoken`.

From this directory run `npm ci` and `npm run dev`, then open the printed localhost address. Select the fixture incident to inspect its timeline, gateway evidence, gaps, and full record. Use the Incidents link or browser Back to return.

Vite proxies /api to the local mock. For an approved lab API, configure VITE_API_BASE and VITE_API_TOKEN for the development session. Browser environment variables are visible to the operator.

Run `npm run gen:types` after contract changes, `npm run typecheck` for strict checks, and `npm run build` for production output. A deployed SPA needs route fallback to index.html and an API proxy or a configured API base.

