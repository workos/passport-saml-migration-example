import { WorkOS } from "@workos-inc/node";
import { fromEnvOrThrow, isProduction } from "./environment";

export const workos = new WorkOS(fromEnvOrThrow("WORKOS_API_KEY"), {
  apiHostname: isProduction ? undefined : "localhost:7000",
  https: isProduction,
});

export const workosClientId = fromEnvOrThrow("WORKOS_CLIENT_ID");
