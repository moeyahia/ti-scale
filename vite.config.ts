import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { meshyWebglBundleBudget } from "./scripts/meshy-webgl-bundle-budget";
import { productionStaticOriginGuard } from "./scripts/production-static-origin-guard";

export default defineConfig(({ command, isPreview, mode }) => {
  const managedPerformanceBuild =
    process.env.TI_SCALE_PERFORMANCE_BUILD === "true";
  // The split development server proxies relative browser requests to its
  // separately managed API process. A production build has no API target:
  // the emitted client retains relative `/api/v2/...` URLs and is served by
  // the same Ti-Scale process that owns port 3132.
  const developmentApiOrigin = command === "serve" && !isPreview
    ? (() => {
        const env = loadEnv(mode, process.cwd(), ["TI_SCALE_", "VITE_TI_SCALE_"]);
        return env.TI_SCALE_API_ORIGIN
          || env.VITE_TI_SCALE_API_ORIGIN
          || "http://127.0.0.1:43141";
      })()
    : undefined;
  return {
    // Managed performance builds inherit a deliberately tiny process
    // environment. Do not let ambient, ignored .env files silently become a
    // second source of client build inputs or a secret-derived provenance
    // oracle.
    envDir: managedPerformanceBuild ? false : undefined,
    plugins: [
      react(),
      tailwindcss(),
      meshyWebglBundleBudget(),
      productionStaticOriginGuard(),
    ],
    // Server-owned TI_SCALE_* values can include credential paths and policy
    // configuration. Vite may read TI_SCALE_API_ORIGIN inside this config for
    // its development proxy, but browser modules may receive only the
    // explicitly client-scoped VITE_TI_SCALE_* namespace.
    envPrefix: "VITE_TI_SCALE_",
    base: "/",
    publicDir: "public",
    server: {
      host: "127.0.0.1",
      port: 43140,
      strictPort: true,
      ...(developmentApiOrigin ? {
        proxy: {
          "/api/v2": { target: developmentApiOrigin, changeOrigin: false },
          "/api/v2/events": { target: developmentApiOrigin, changeOrigin: false },
        },
      } : {}),
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
