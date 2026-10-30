import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export default {
  content: [join(here, "index.html"), join(here, "src/**/*.{ts,tsx}")],
  theme: {
    extend: {
      colors: {
        ink: { 950: "#0a101c", 900: "#0e1524", 850: "#111a2b", 800: "#172236", 700: "#22304a", 600: "#33445f" },
        text: { 1: "#e8edf5", 2: "#a9b5c7", 3: "#74829a" },
        accent: { DEFAULT: "#38bdf8", dim: "#0c4a6e" },
        good: "#34d399", warn: "#fbbf24", crit: "#f87171",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SF Mono", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
};
