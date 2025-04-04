import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  server: {
    port: 8080,
  },
  plugins: [
    react(),
    mode === 'development' &&
    componentTagger(),
  ].filter(Boolean),
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    outDir: "dist",
    sourcemap: mode !== "production",
    // Ensure paths are relative for Vercel deployment
    assetsDir: "assets",
  },
  preview: {
    // Setup SPA fallback for client-side routing
    port: 8080,
    host: true,
  },
  // Support client-side routing by redirecting all requests to index.html
  appType: 'spa', // Enable SPA mode for proper routing
}));
