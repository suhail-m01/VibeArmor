import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    allowedHosts: true,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("error", (_err, _req, res) => {
            if (res && "writeHead" in res && !res.headersSent) {
              res.writeHead(503, { "Content-Type": "application/json" });
              res.end(
                JSON.stringify({
                  detail:
                    "VibeArmor Python Backend (127.0.0.1:8000) is starting up or offline — run `npm run dev` (which auto-starts both backend & UI) or `start_studio.ps1`.",
                })
              );
            }
          });
        },
      },
    },
  },
});
