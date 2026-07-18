import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), ["TI_SCALE_", "VITE_TI_SCALE_"]);
  const apiOrigin = env.TI_SCALE_API_ORIGIN || env.VITE_TI_SCALE_API_ORIGIN || "http://127.0.0.1:43141";
  return {
    plugins: [react(), tailwindcss()],
    envPrefix: ["TI_SCALE_", "VITE_TI_SCALE_"],
    base: "/",
    publicDir: "public",
    server: {
      host: "127.0.0.1",
      port: 43140,
      strictPort: true,
      proxy: {
        "/api/v2": { target: apiOrigin, changeOrigin: false },
        "/api/v2/events": { target: apiOrigin, changeOrigin: false },
      },
    },
    preview: {
      host: "127.0.0.1",
      port: 43140,
      strictPort: true,
    },
    build: {
      outDir: "dist",
      emptyOutDir: true,
      sourcemap: true,
      target: "es2022",
      rollupOptions: {
        output: {
          manualChunks: {
            react: ["react", "react-dom"],
          },
        },
      },
    },
  };
});
