import { defineConfig } from "vite";

// Local fixture server only. The lab gateway owns deployed authentication.
export default defineConfig({
  server: {
    host: "127.0.0.1",
    proxy: {
      "^/api/v1/incidents(?:/[^/?]+)?(?:[?].*)?$": {
        target: "http://127.0.0.1:8000",
        configure(proxy) {
          proxy.on("proxyReq", (request, incoming) => {
            request.removeHeader("authorization");
            if (incoming.method === "GET" && process.env.NEXUS_MOCK_TOKEN) {
              request.setHeader("Authorization", "Bearer " + process.env.NEXUS_MOCK_TOKEN);
            }
          });
        },
      },
    },
  },
  preview: { proxy: {} },
});
