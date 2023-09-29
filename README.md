# `passport-saml` Migration Example

This example demonstrates a migration path from a custom SSO implementation running on `passport-saml` to a SSO implementation to WorkOS.

## Try it

#### 1. Clone the repo and install dependencies
```
git clone https://github.com/workos/passport-saml-migration-example.git
cd passport-saml-migration-example
npm i
```

#### 2. Establish a tunnel
Using `ngrok`, we prepare a tunnel to port 3000 on our local machine, and obtain the forwarding URL.

```
ngrok http 3000
```

Make note of the Forwarding URL, which will look something like `https://7736-2001-871-216-2b68-69bd-a3bb-d4d6-af3f.ngrok-free.app`.  This will be used in the next step.

#### 3. Set up a demo IDP, and configure the example app accordingly

Copy the `.env.example` to `.env`, and edit it with your specific env variables
```
cp .env.example .env
```

Guidence for common identity providers can be found from the [WorkOS SSO Quickstart](https://workos.com/docs/sso).
**However**, we wish to configure the IDP in its "pre-migration" state, therefore we will deviate from the standard WorkOS instructions, omiting WorkOS, and configure the IDP to point directly to our `passport-saml` example.

Create an APP in your IDP of choice, setting the following:

- **Entity ID** - Sometimes called the "Issuer", this effectively a name of your app.  Set it to be the public URL of the example app, i.e. `https://7736-2001-871-216-2b68-69bd-a3bb-d4d6-af3f.ngrok-free.app`.  Set the value of the `EXAMPLE_ISSUER` env variable to the same.
- **ACS URL** - Sometimes called the "SSO URL", this is the path to the SAML callback in the example app, via the tunnel.  Its value will be your tunnel host combined with the `/authenticate/callback` path, i.e.:   `https://7736-2001-871-216-2b68-69bd-a3bb-d4d6-af3f.ngrok-free.app/authenticate/callback`.  Set the `EXAMPLE_SSO_URL` env var to this value also.
- **Public Certificate** - Copy the x509 public certificate provided by the IDP, and use it for the `EXAMPLE_IDP_PUBLIC_CERT` env variable.

#### 4. Create a Configure WorkOS settings

We will configure the WorkOS side of things, which will be our "post-migration" state.

- `WORKOS_CLIENT_ID` and `WORKOS_API_KEY` are obtained from the WorkOS dashboard, on the "API Keys" page.
- In the WorkOS Dashboard, visit the Configuration page and add a new "Sign in callback".  Its value will be your tunnel host combined with a `/workos/callback` path; i.e. ``https://7736-2001-871-216-2b68-69bd-a3bb-d4d6-af3f.ngrok-free.app/workos/callback`.  Set the `WORKOS_CALLBACK_URL`
- In the WorkOS dashboard, create an organization representing one of your customers.
- Under the "Single Sign On" feature, create a new connection matching the IDP you selected.
- Copy the Connection ID to the `EXAMPLE_WORKOS_CONNECTION_ID` env var
- Copy the ACS URL to the `EXAMPLE_WORKOS_CONNECTION_ACS_URL` env var

#### 4. Run it

```
npm run dev
```
And visit your app via the ngrok tunnel.

#### 5. Sign in via passport-saml

In this example, the switch between signing in via `passport-saml` and via WorkOS is controlled by a user input.  In a real-world scenario, this should be determined by your app, such as by a feature flag.

First, sign in using only passport-saml.  You should be presented with a login flow on the IDP, and returned to the example app, showing your email address.

#### 6. Sign in via WorkOS

Log out, and log in again, selecting "WorkOS SSO" as the method.  You should again be logged in, but this time via WorkOS.  You can view the authenticated sessions in the Sessions tab of the connection page in the WorkOS dashboard.

