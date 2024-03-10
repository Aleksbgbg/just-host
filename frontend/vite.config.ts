import eslint from "@nabla/vite-plugin-eslint";
import vue from "@vitejs/plugin-vue";
import dotenv from "dotenv";
import { resolve } from "path";
import { defineConfig } from "vite";
import checker from "vite-plugin-checker";

dotenv.config();

export default defineConfig({
  plugins: [
    vue(),
    eslint(),
    checker({
      vueTsc: true,
    }),
  ],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  server: {
    host: "0.0.0.0",
    port: parseInt(process.env.APP_PORT, 10),
    strictPort: true,
    proxy: {
      "/api": `http://${process.env.DEBUG_FORWARD_HOST}:${process.env.DEBUG_FORWARD_PORT}`,
    },
  },
});
