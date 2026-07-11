import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/main.ts", "src/mcp-bin.ts"],
  format: ["esm"],
  target: "node20",
  // Bundle the workspace packages (they ship TS source) so the output is deployable;
  // keep real npm deps external (installed in the image's node_modules).
  noExternal: [/^@frisk\//],
  clean: true,
  sourcemap: true,
});
