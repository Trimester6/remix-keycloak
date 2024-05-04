# Remix Auth for Keycloak
<a href="https://nodei.co/npm/remix-keycloak/"><img src="https://nodei.co/npm/remix-keycloak.png?mini=true"></a>

This repository is based on existing repository by [@mlcsthor](https://github.com/mlcsthor/remix-auth-keycloak/)

I took it on myself to maintain it because original maintainer decided to archive existing repository on December 2nd 2023. 

Some tweaks were introduced for easier maintenance and easier readibility.

Reason behind is that we are using it for our project over at [Cybernite Intelligence](https://github.com/Cybernite-Intelligence-Inc/)

This package supports both Remix v1 and Remix v2.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |
| Netlify | ✅          |


## Table of Contents
- [Remix Auth for Keycloak](#remix-auth-for-keycloak)
  - [Supported runtimes](#supported-runtimes)
  - [Table of Contents](#table-of-contents)
  - [KeycloakStrategy ](#keycloakstrategy-)
  - [Getting Started ](#getting-started-)
  - [Usage ](#usage-)
    - [Create strategy instance](#create-strategy-instance)
    - [Setting up your routes](#setting-up-your-routes)

## KeycloakStrategy <a name = "keycloak-strategy"></a>

The Keycloak strategy is used to authenticate users against an Keycloak account. It extends the OAuth2Strategy.

## Getting Started <a name = "getting_started"></a>

All you have to do to add package to your existing Remix V1 or Remix v2 
project is run:

```
npm i remix-keycloak
```

## Usage <a name = "usage"></a>

### Create strategy instance

```tsx
// app/utils/auth.server.ts
import { Authenticator } from "remix-auth";
import { KeycloakStrategy } from "remix-keycloak";

// Create an instance of the authenticator, pass a generic with what your
// strategies will return and will be stored in the session
export const authenticator = new Authenticator<User>(sessionStorage);

let keycloakStrategy = new KeycloakStrategy(
  {
    useSSL: true,
    domain: "example.app",
    realm: "example",
    clientID: "YOUR_CLIENT_ID",
    clientSecret: "YOUR_CLIENT_SECRET",
    callbackURL: "your.app/callback",
  },
  async ({ accessToken, refreshToken, extraParams, profile }) => {
    // Get the user data from your DB or API using the tokens and profile
    return User.findOrCreate({ email: profile.emails[0].value });
  }
);

authenticator.use(keycloakStrategy);
```
### Setting up your routes

```tsx
// app/routes/login.tsx
export default function Login() {
  return (
    <Form action="/auth/keycloak" method="post">
      <button>Login with Keycloak</button>
    </Form>
  );
}
```
```tsx
// app/routes/auth/keycloak.tsx
import type { ActionFunction, LoaderFunction } from "remix";

import { authenticator } from "~/utils/auth.server";

export let loader: LoaderFunction = () => redirect("/login");

export let action: ActionFunction = ({ request }) => {
  return authenticator.authenticate("keycloak", request);
};
```
```tsx
// app/routes/auth/keycloak/callback.tsx
import type { ActionFunction, LoaderFunction } from "remix";

import { authenticator } from "~/utils/auth.server";

export let loader: LoaderFunction = ({ request }) => {
  return authenticator.authenticate("keycloak", request, {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  });
};
```
