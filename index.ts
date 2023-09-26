import "dotenv/config";

import express from "express";
import passport from "passport";
import session from "express-session";
import { fromEnvOrThrow, isProduction } from "./src/environment";
import { MultiSamlStrategy, Profile, VerifiedCallback } from "passport-saml";
import { SamlConfigStore } from "./src/saml-config-store";
import { User, UserStore } from "./src/user-store";

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

app.post("/authenticate", passport.authenticate("saml"));
app.post(
  "/authenticate/callback",
  passport.authenticate("saml", { failureRedirect: "/", failureMessage: true }),
  (_req, res) => {
    res.redirect("/");
  },
);

const port = process.env.PORT ?? 3000;

app.listen(port, () => {
  console.info(`Listening on port ${port}...`);
});
