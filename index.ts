import "dotenv/config";

import express, { Request } from "express";
import passport from "passport";
import session from "express-session";
import { fromEnvOrThrow, isProduction } from "./src/environment";
import { MultiSamlStrategy, Profile, VerifiedCallback } from "passport-saml";
import { SamlConfigStore } from "./src/saml-config-store";
import { User, UserStore } from "./src/user-store";
import { workos, workosClientId } from "./src/workos";
import cookieParser from "cookie-parser";

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

passport.use(
  new MultiSamlStrategy(
    {
      getSamlOptions: (req, done) => {
        const { cert, issuer, ssoUrl } = new SamlConfigStore().findByRequest(
          req,
        );

        done(null, {
          path: "/authenticate/callback",
          entryPoint: ssoUrl.toString(),
          issuer,
          cert,
        });
      },
    },
    (profile: Profile | null | undefined, done: VerifiedCallback) => {
      if (!profile) {
        return done(new Error("Profile is missing."));
      }

      if (!profile.email) {
        return done(new Error("Profile is missing an email."));
      }

      const user = new UserStore().findByEmail(profile.email);

      done(null, user as unknown as Record<string, unknown>);
    },
  ),
);

// Simply store the entire user object in the session for demo purposes.
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user as User));

app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("root", { user: req.user });
});

app.get("/login", (req, res) => {
  if (req.user) {
    return res.redirect("/");
  }

  res.render("login");
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/login");
  });
});

app.post(
  "/authenticate",
  (req, res, next) => {
    // This should normally be determined by persisted configuration in a
    // database or a feature flag, but using a form parameter for demo purposes.
    const method = req.body.sso_provider ?? "passport";

    switch (method) {
      case "workos":
        res.cookie("sso_provider", "workos", { httpOnly: true, maxAge: 30000 });
        res.redirect(
          workos.sso.getAuthorizationURL({
            redirectURI: "http://localhost:3000/workos/callback",
            clientID: workosClientId,
            connection: fromEnvOrThrow("EXAMPLE_WORKOS_CONNECTION_ID"),
          }),
        );
        break;
      case "passport":
        res.cookie("sso_provider", "passport", {
          httpOnly: true,
          maxAge: 30000,
        });
        next();
        break;
      default:
        next();
    }
  },
  passport.authenticate("saml"),
);
app.post(
  "/authenticate/callback",
  (req, res, next) => {
    if (req.cookies.sso_provider === "workos") {
      return res.render("saml-post-response", {
        acsUrl: fromEnvOrThrow("EXAMPLE_WORKOS_CONNECTION_ACS_URL"),
        samlResponse: req.body.SAMLResponse,
        relayState: req.body.RelayState,
      });
    }

    next();
  },
  passport.authenticate("saml", { failureRedirect: "/", failureMessage: true }),
  (_req, res) => {
    res.redirect("/");
  },
);

app.get("/workos/callback", async (req, res) => {
  if (!(typeof req.query.code === "string")) {
    res.status(400);
    return res.send("400");
  }

  const { profile } = await workos.sso.getProfileAndToken({
    code: req.query.code,
    clientID: workosClientId,
  });

  console.info({ profile });

  res.send("WorkOS Callback");
});

const port = process.env.PORT ?? 3000;

app.listen(port, () => {
  console.info(`Listening on port ${port}...`);
});
