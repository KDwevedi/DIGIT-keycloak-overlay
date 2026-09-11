import { closeCache, initCache } from "./cache.js";
import { config } from "./config.js";
import { createIdentityApp } from "./identity-app.js";
import { initJwks } from "./jwt.js";

initJwks();
initCache();

const app = createIdentityApp();
const server = app.listen(config.port, () => {
  console.log(`digit-identity-bff listening on :${config.port}`);
});

process.on("SIGTERM", () => {
  server.close(() => {
    void closeCache().finally(() => process.exit(0));
  });
});
