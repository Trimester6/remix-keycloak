import type { StrategyVerifyCallback } from "remix-auth";
import type {
  OAuth2Profile,
  OAuth2StrategyVerifyParams,
} from "remix-auth-oauth2";
import { OAuth2Strategy } from "remix-auth-oauth2";

export interface KeycloakStrategyOptions {
  useSSL?: boolean;
  domain: string;
  realm: string;
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string;
}

export interface KeycloakExtraParams extends Record<string, string | number> {
  id_token: string;
  scope: string;
  expires_in: 86_400;
  token_type: "Bearer";
}

export interface KeycloakProfile extends OAuth2Profile {
  id: string;
  displayName: string;
  name: {
    familyName: string;
    givenName: string;
  };
  emails: [{ value: string }];
  _json: {
    sub: string;
    email: string;
    email_verified: boolean;
    preferred_username: string;
    name: string;
    given_name: string;
    family_name: string;
  };
}

export class KeycloakStrategy<User> extends OAuth2Strategy<
  User,
  KeycloakProfile,
  KeycloakExtraParams
> {
  name = "keycloak";

  private userInfoURL: string;
  private scope: string;

  constructor(
    {
      useSSL = false,
      domain,
      realm,
      clientID,
      clientSecret,
      callbackURL,
      scope = "openid profile email",
    }: KeycloakStrategyOptions,
    verify: StrategyVerifyCallback<
      User,
      OAuth2StrategyVerifyParams<KeycloakProfile, KeycloakExtraParams>
    >
  ) {
    const host = `${useSSL ? "https" : "http"}://${domain}`;

    super(
      {
        authorizationURL: `${host}/realms/${realm}/protocol/openid-connect/auth`,
        tokenURL: `${host}/realms/${realm}/protocol/openid-connect/token`,
        clientID,
        clientSecret,
        callbackURL,
      },
      verify
    );

    this.userInfoURL = `${host}/realms/${realm}/protocol/openid-connect/userinfo`;
    this.scope = scope;
  }

  protected authorizationParams() {
    const urlSearchParams = { scope: this.scope };
    return new URLSearchParams(urlSearchParams);
  }

  protected async userProfile(accessToken: string): Promise<KeycloakProfile> {
    try {
      const headers = new Headers({ Authorization: `Bearer ${accessToken}` });
      const response = await fetch(this.userInfoURL, { headers });
      const data = await response.json();

      const profile: KeycloakProfile = {
        provider: "keycloak",
        displayName: data.name,
        id: data.sub,
        name: {
          familyName: data.family_name,
          givenName: data.given_name,
        },
        emails: [{ value: data.email }],
        _json: data,
      };

      return profile;
    } catch (error) {
      console.error("Error fetching user profile:", error);
      throw error;
    }
  }
}
