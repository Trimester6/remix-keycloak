import type { StrategyVerifyCallback } from "remix-auth";
import type {
  OAuth2Profile,
  OAuth2StrategyVerifyParams,
} from "remix-auth-oauth2";
import { OAuth2Strategy } from "remix-auth-oauth2";

/**
 * Options for configuring the Keycloak authentication strategy.
 */
export interface KeycloakStrategyOptions {
  useSSL?: boolean; // Whether to use SSL for Keycloak server communication.
  domain: string; // Keycloak server domain.
  realm: string; // Keycloak realm.
  clientID: string; // Client ID for the registered application in Keycloak.
  clientSecret: string; // Client Secret for the registered application in Keycloak.
  callbackURL: string; // URL to which Keycloak will redirect the user after authentication.
  scope?: string; // Optional scopes for Keycloak authentication.
}

/**
 * Additional parameters returned in the Keycloak user profile.
 */
export interface KeycloakExtraParams extends Record<string, string | number> {
  id_token: string; // ID token issued by Keycloak.
  scope: string; // Scopes granted by the user.
  expires_in: 86_400; // Expiry time for the token.
  token_type: "Bearer"; // Token type.
}

/**
 * User profile structure specific to Keycloak authentication.
 */
export interface KeycloakProfile extends OAuth2Profile {
  id: string; // Unique user ID.
  displayName: string; // Display name of the user.
  name: {
    familyName: string; // Family name of the user.
    givenName: string; // Given name of the user.
  };
  emails: [{ value: string }]; // User's email(s).
  _json: {
    sub: string; // Keycloak subject identifier.
    email: string; // User's email.
    email_verified: boolean; // Email verification status.
    preferred_username: string; // Preferred username.
    name: string; // Full name of the user.
    given_name: string; // Given name of the user.
    family_name: string; // Family name of the user.
  };
}

/**
 * Keycloak authentication strategy implementation.
 */
export class KeycloakStrategy<User> extends OAuth2Strategy<
  User,
  KeycloakProfile,
  KeycloakExtraParams
> {
  name = "keycloak"; // Strategy name.

  private userInfoURL: string; // URL to fetch user information from Keycloak.
  public scope: string; // Scopes for Keycloak authentication.

  /**
   * Constructor for the Keycloak authentication strategy.
   * @param options - Configuration options for the Keycloak strategy.
   * @param verify - Verify callback function to validate user identity.
   */
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

    // Call the constructor of the parent OAuth2Strategy class with Keycloak-specific parameters.
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

    // Set Keycloak-specific URLs and scope.
    this.userInfoURL = `${host}/realms/${realm}/protocol/openid-connect/userinfo`;
    this.scope = scope;
  }

  /**
   * Custom method to provide additional authorization parameters specific to Keycloak.
   * @returns URLSearchParams containing the specified scope.
   */
  protected authorizationParams() {
    const urlSearchParams = { scope: this.scope };
    return new URLSearchParams(urlSearchParams);
  }

  /**
   * Custom method to fetch and parse the user profile from Keycloak.
   * @param accessToken - Access token obtained during the authentication process.
   * @returns Promise resolving to the Keycloak user profile.
   */
  protected async userProfile(accessToken: string): Promise<KeycloakProfile> {
    try {
      const headers = new Headers({ Authorization: `Bearer ${accessToken}` });
      const response = await fetch(this.userInfoURL, { headers });
      const data = await response.json();

      // Construct a KeycloakProfile object from the received data.
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
