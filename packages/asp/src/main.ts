/** HTTP entrypoint — boots the Frisk ASP. */
import { loadConfig } from "./config.js";
import { createServer } from "./server.js";

const cfg = loadConfig();
const app = createServer(cfg);
app.listen(cfg.port, () => {
  // eslint-disable-next-line no-console
  console.log(`Frisk ASP listening on :${cfg.port} (${cfg.network}, devBypass=${cfg.devBypass})`);
});
