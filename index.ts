import "dotenv/config";

import URL from "node:url";
import express from "express";
import passport from "passport";
import session from "express-session";
import { fromEnvOrThrow, isProduction } from "./src/environment";
import { MultiSamlStrategy, Profile, VerifiedCallback } from "passport-saml";
import { SamlConfigStore } from "./src/saml-config-store";
import { User, UserStore } from "./src/user-store";
import cookieParser from "cookie-parser";
import { WorkOsSsoStrategy } from "./src/workos-strategy";

// Standard setup for an Express application that uses Passport, so we can
// hand-wave all of this.
const app = express();
app.set("view engine", "pug");
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    cookie: { secure: isProduction },
    resave: true,
    saveUninitialized: true,
    secret: fromEnvOrThrow("SESSION_SECRET"),
  }),
);
app.use(cookieParser());

// `MultiSamlStrategy` is the Passport strategy we'll be migrating away from. Note
// that we use the _MultiSamlStrategy_, which represents an application that can
// delegate to multiple different SAML identity providers (IdP's) for authentication.
// This is the more common strategy for most multi-tenant applications.
passport.use(
  new MultiSamlStrategy(
    {
      // We need to specify `getSamlOptions` in order to return the relevant SAML
      // configuration to initiate authentication for the current request.
      getSamlOptions: (req, done) => {
        // It varies by application how the configuration would be determined retrieved
        // based on the request, so this is abstracted away in the `SamlConfigStore`.
        //
        // Here are some real-world strategies applications might use:
        //
        //   * Prompt the user -- Have the user tell you which organization they
        //     are attempting to sign in to.
        //   * Email domain -- Have the user enter their email address first and then use
        //     the email domain to locate their organization.
        //   * Request Host -- If each tenant of the application gets their own
        //     subdomain, then the application can use the `Host` header of the request
        //     to locate the user's organization.
        //
        // You can find more information about sign-in UX strategies in the WorkOS docs:
        //
        //   https://workos.com/docs/sso/ux/sign-in
        //
        // We'll continue to use this `SamlConfigStore` later to lookup relevant migration
        // configuration.
        const { cert, issuer, ssoUrl } = new SamlConfigStore().findByRequest(
          req,
        );

        done(null, {
          protocol: `${URL.parse(fromEnvOrThrow("EXAMPLE_ISSUER")).protocol}//`,
          host: URL.parse(fromEnvOrThrow("EXAMPLE_ISSUER")).host ?? undefined,
          path: "/authenticate/callback",
          entryPoint: ssoUrl.toString(),
          issuer,
          cert,
        });
      },
    },
    // # Passport Refresher:
    //
    // This callback takes the "profile", which is a representation of the authenticated
    // user from the IdP, and looks up the "real" user object from the application's
    // persistence layer.
    //
    // Later, Passport passed this object to `serializeUser` which we'll talk more
    // about there.
    (profile: Profile | null | undefined, done: VerifiedCallback) => {
      if (!profile) {
        return done(new Error("Profile is missing."));
      }

      if (!profile.email) {
        return done(new Error("Profile is missing an email."));
      }

      // In a real application, `UserStore` might make perform a Database query to
      // retrieve the user object.
      const user = new UserStore().findByEmail(profile.email);

      done(null, user as unknown as Record<string, unknown>);
    },
  ),
);

// The `WorkOsSsoStrategy` is the Passport strategy we'll be migrating towards. The code
// is a very thin wrapper around the WorkOS SDK in order to integrate with Passport. Check
// out the WorkOS example apps if you'd like to see how a Node app might implement SSO
// without integrating with Passport:
//
//   https://github.com/workos/node-example-applications
//
// For this example, we'll choose to implement WorkOS as a Passport strategy to minimize
// the differences to the rest of the application.
passport.use(
  new WorkOsSsoStrategy(
    {
      clientID: fromEnvOrThrow("WORKOS_CLIENT_ID"),
      clientSecret: fromEnvOrThrow("WORKOS_API_KEY"),
      callbackURL: fromEnvOrThrow("WORKOS_CALLBACK_URL"),
    },
    (_req, _accessToken, _refresh_token, profile, done) => {
      // Similar to the `MultiSamlStrategy`, this second callback takes the `profile` and
      // looks up the user in the application's persistence.
      //
      // Note that here we use `findByProfile`. In a real application, take care to scope
      // any lookups by the profile's `organizationId`, in addition to other fields like
      // the profile's ID or email.
      const user = new UserStore().findByProfile(profile);

      done(null, user);
    },
  ),
);

// # Passport Refresher:
//
// These two functions are responsible for saving the user into the session, or recalling it
// from the session. This might normally look like `serializeUser` plucking the user's ID,
// and then `deserializeUser` taking that plucked ID and calling `done` with the user after
// looking it up in a database.
//
// Since this is just an example, we'll serialize the entire user object in order to keep
// things simple.
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user as User));

// Standard boilerplate when adding Passport to an Express application.
app.use(passport.initialize());
app.use(passport.session());

// These next three routes are here to facilitate the example login and logout pages. There
// isn't much notable about them, and so we'll skip over them quickly.
app.get("/", (req, res) => res.render("root", { user: req.user }));
app.get("/login", (req, res) =>
  req.user ? res.redirect("/") : res.render("login"),
);
app.get("/logout", (req, res) => req.logout(() => res.redirect("/login")));

// This endpoint is the crux of the migration process. It either sends the user down the
// legacy `passport-saml`-based SSO flow, or uses the new WorkOS SSO strategy.
app.post("/authenticate", (req, res, next) => {
  const config = new SamlConfigStore();

  // For applications that wish to incrementally roll-out WorkOS to their existing SSO users,
  // they can choose between various techniques to controlling when this
  // `getProviderByRequest` call returns either `"workos"` or `"passport"`.
  //
  // For example, use of feature flags targeted at specific tenants. Or, a staged roll-out
  // where only an X% of customers use the new flow.
  //
  // Once things look good, eventually this will return `"workos"` for all users. When it
  // does, the `"passport"` case, along with other `passport-saml`-related coded, can be
  // removed entirely.
  const method = config.getProviderByRequest(req);

  // Note the usage of a cookie here. When the user later comes back from the IdP at the
  // `/authenticate/callback` endpoint, we can look at this cookie value to determine
  // which path the user should continue down. This helps to ensure that we don't start
  // users down the old flow, but then attempt to enter them into the new flow when
  // they come back, in case the `getProviderByRequest` would have later returned a
  // different value.
  res.cookie("sso_provider", method, { httpOnly: true, maxAge: 30000 });

  switch (method) {
    case "workos":
      const { workosConnectionId } = config.findByRequest(req);

      passport.authenticate("workos")(
        {
          ...req,
          workOsSelector: { connection: workosConnectionId },
        },
        res,
        next,
      );
      break;
    case "passport":
      passport.authenticate("saml")(req, res, next);
      break;
  }
});

// Here's the original `passport-saml` callback endpoint. Normally, this would only
// consist of the call to the Passport authenticate middleware:
//
//   passport.authenticate("saml", { successRedirect: "/" }),
//
// In this case have an additional middleware before it.
app.post(
  "/authenticate/callback",
  // IdP's that still have an ACS URL configured to point directly to the application
  // (rather than WorkOS) will continue to send users here. We need to handle those
  // responses by forwarding them to WorkOS.That's what this middleware does.
  //
  // We use the SAML POST binding to take the SAML response that was received
  // and "RePOST" it to WorkOS. You can read more about that binding here:
  //
  //   https://en.wikipedia.org/wiki/SAML_2.0#HTTP_POST_Binding
  //
  // In short, the SAML spec outlines it as a self-submitting form with two parameters;
  // the `SAMLResponse` and the `RelayState`. This is actually the same binding that the
  // IdP originally used to send the response. The application can use the same method
  // to forward the response to WorkOS.
  (req, res, next) => {
    // First, we check for the presence and value of the cookie from earlier...
    if (req.cookies.sso_provider === "workos") {
      // The WorkOS ACS URL can be found in the WorkOS dashboard when viewing a connection.
      const { workosAcsUrl } = new SamlConfigStore().findByRequest(req);

      // If the cookie is set, we respond with the POST binding. Check out the
      // template in `views` to see how to implement it. It's pretty simple.
      return res.render("saml-post-response", {
        acsUrl: workosAcsUrl,
        samlResponse: req.body.SAMLResponse,
        relayState: req.body.RelayState,
      });
    }

    // ...otherwise, we forward the request to the "next" middleware, which is the old
    // `passport-saml` middleware. Eventually no users will make it here, and the following
    // middleware can be removed.
    next();
  },
  passport.authenticate("saml", { successRedirect: "/" }),
);

// The standard WorkOS callback. There isn't any migration specific logic needed
// here. Check out the WorkOS docs for more information about how to normally
// implement this endpoint:
//
//    https://workos.com/docs/sso/2-add-sso-to-your-app/add-a-callback-endpoint
//
app.get(
  "/workos/callback",
  passport.authenticate("workos", { successRedirect: "/" }),
);

// The last of the boilerplate. Start the app!
const port = process.env.PORT ?? 3000;
app.listen(port, () => {
  console.info(`Listening on port ${port}...`);
});
