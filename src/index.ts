// Entrypoint. Starts the HTTP server on PORT (default 3000).
// The platform requires a PUBLIC HTTPS endpoint — terminate TLS in front
// of this service (reverse proxy / load balancer / hosting platform).
import { config } from "./config.js";
import { createHttpServer } from "./server.js";

const server = createHttpServer();
server.listen(config.port, () => {
  console.log(`[steal-vfy] listening on :${config.port} (path ${config.agentPath})`);
  console.log(`[steal-vfy] network=${config.kurierNetwork} registeredVk=${config.registeredVkHash.slice(0, 14)}...`);
  console.log(`[steal-vfy] health: GET /health`);
});

process.on("SIGTERM", () => server.close(() => process.exit(0)));
process.on("SIGINT", () => server.close(() => process.exit(0)));
