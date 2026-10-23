/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run live` starts server/live.ts on 8787; the dev server proxies the
// WebSocket to it. `npm run demo` never needs it.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8787", ws: true },
    },
  },
  test: {
    include: ["test/**/*.test.ts"],
  },
});
