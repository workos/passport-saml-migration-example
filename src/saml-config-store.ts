import { Request } from "express";
import { fromEnvOrThrow } from "./environment";

export interface SamlConfig {
  ssoUrl: URL;
  issuer: string;
  cert: string;
}

/**
 * A stand-in for a persistence layer storing SAML configuration that
 * would exist in a real-world application.
 */
export class SamlConfigStore {
  /**
   * A real application might use information from the request, like
   * the `Host`, to determine which SAML configuration to use. However,
   * we always return the "example" information from the environment for
   * demonstration purposes.
   */
  findByRequest(_req: Request): SamlConfig {
    return {
      ssoUrl: new URL(fromEnvOrThrow("EXAMPLE_SSO_URL")),
      issuer: fromEnvOrThrow("EXAMPLE_ISSUER"),
      cert: fromEnvOrThrow("EXAMPLE_IDP_PUBLIC_CERT"),
    };
  }
}
