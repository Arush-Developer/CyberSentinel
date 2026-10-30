import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export default { plugins: { tailwindcss: { config: join(here, "tailwind.config.js") }, autoprefixer: {} } };
