/**
 * Vendored from `https://github.com/andyrichardson/passport-workos` with
 * some small changes, like allowing passing options to the underlying `WorkOS`
 * client, and general type cleanups.
 */

import { AuthenticateOptions, Strategy } from "passport";
import { Request } from "express";
import WorkOS, { Profile, OauthException } from "@workos-inc/node";

export type WorkOsSsoStrategyOptions = {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  clientOptions?: ConstructorParameters<typeof WorkOS>[1];
};

export type WorkOsSsoStrategyVerifyFn = (
  req: Request,
  accessToken: string,
  refreshToken: string | undefined,
  profile: Profile,
  cb: (err: unknown | null, user: Express.User, info?: {}) => void,
) => void;

type RequestWithWorkOsSelector = Request & {
  workOsSelector: {
    connection?: string;
    organization?: string;
    provider?: string;
  };
};

export class WorkOsSsoStrategy extends Strategy {
  override name = "workos";

  private readonly client: WorkOS;

  constructor(
    private readonly options: WorkOsSsoStrategyOptions,
    private readonly verify: WorkOsSsoStrategyVerifyFn,
  ) {
    super();
    this.client = new WorkOS(options.clientSecret, options.clientOptions);
  }

  public authenticate(
    req: RequestWithWorkOsSelector,
    options: AuthenticateOptions,
  ) {
    if (req.query?.code) {
      return this._loginCallback(req, options);
    }

    return this._loginAttempt(req, options);
  }

  private _loginAttempt(
    req: RequestWithWorkOsSelector,
    options: AuthenticateOptions,
  ) {
    try {
      const { connection, organization, provider } = req.workOsSelector;
      if ([connection, organization, provider].every((selector) => !selector)) {
        throw Error(
          "One of 'connection', 'organization', and/or 'provider' are required",
        );
      }

      const url = this.client.sso.getAuthorizationURL({
        ...req.body,
        connection,
        organization,
        provider,
        clientID: this.options.clientID,
        redirectURI: this.options.callbackURL,
        ...options,
      });

      this.redirect(url);
    } catch (err: unknown) {
      if (err instanceof Error) {
        this.fail(err.message);
      }

      this.fail("Unknown error while constructing a WorkOS authorization URL.");
    }
  }

  private async _loginCallback(req: Request, _options: AuthenticateOptions) {
    try {
      const { profile, accessToken } = await this.client.sso.getProfileAndToken(
        {
          code: req.query.code as string,
          clientID: this.options.clientID,
        },
      );

      this.verify(
        req,
        accessToken,
        undefined /* no refresh token */,
        profile,
        (err: unknown, user: Express.User, info?: {}) => {
          if (err) {
            return this.error(err);
          }

          if (!user) {
            return this.fail("no user");
          }

          return this.success(user, info);
        },
      );
    } catch (err: unknown) {
      if (err instanceof OauthException) {
        return this.fail(err.errorDescription);
      }

      return this.error(err);
    }
  }
}
