# NEXUS incident dashboard

## Local fixture

From the repository root, start the mock API in the Python tools environment. The mock CLI listens on all interfaces, so use a local development machine with appropriate network restrictions.

    python tools/mock_server.py --port 8000 --token devtoken

In a second PowerShell terminal, from dashboard/, run:

    $env:NEXUS_MOCK_TOKEN = "devtoken"
    npm ci
    npm run dev

Open the printed loopback address and select the fixture incident. The browser requests the incident list and detail from the same origin. The Vite development proxy attaches the explicitly configured mock token to GET requests to the local fixture API. An unset token produces an unauthenticated request. Use only the disposable mock credential here.

## Lab deployment proposal for Rakan

Serve the dashboard and /api/v1 on one HTTPS origin. The gateway should authenticate each analyst, issue a Secure, HttpOnly, SameSite session cookie, and authorize incident reads for that analyst. Keep any upstream service credential on the gateway. Rakan and Bashar should agree on session issuance, expiry and authorization before connecting the SPA to the lab. The standalone static build expects a same-origin API and history fallback for UI routes.

## Checks

Run npm run gen:types after contract changes. npm run typecheck runs strict TypeScript checks. npm run build checks types and builds the production assets.
