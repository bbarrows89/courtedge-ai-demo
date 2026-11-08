import type { NextAuthOptions } from 'next-auth';
import OktaProvider from 'next-auth/providers/okta';
import { createPrivateKey, createSign, randomUUID } from 'crypto';

// -----------------------------------------------------------------------------
// Replacement for packages/progear-sales-agent/src/lib/auth.ts
//
// Why: since O4AA "client binding", the AI agent and its sign-in app share ONE
// client authentication method. If the agent uses a public/private key, Okta's
// token endpoint rejects NextAuth's default client_secret login with
// "invalid_client". This version signs the authorization-code exchange with the
// agent's private key (private_key_jwt) when no OKTA_CLIENT_SECRET is set.
//
// Needs a server-only env var in Vercel (NOT NEXT_PUBLIC_): OKTA_AI_AGENT_PRIVATE_KEY
// (the single-line JWK). If OKTA_CLIENT_SECRET is set, the original secret flow is used.
// -----------------------------------------------------------------------------

const issuer = process.env.NEXT_PUBLIC_OKTA_ISSUER!; // Org URL, e.g. https://your-org.okta.com
const clientId = process.env.NEXT_PUBLIC_OKTA_CLIENT_ID!;
const tokenEndpoint = `${issuer}/oauth2/v1/token`; // Org authorization server

const usePrivateKeyJwt =
  !process.env.OKTA_CLIENT_SECRET && !!process.env.OKTA_AI_AGENT_PRIVATE_KEY;

const b64u = (v: Buffer | string) => Buffer.from(v).toString('base64url');

// RS256-signed client assertion (RFC 7523), valid for 60 seconds.
function buildClientAssertion(): string {
  const jwk = JSON.parse(process.env.OKTA_AI_AGENT_PRIVATE_KEY!);
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT', kid: jwk.kid };
  const payload = {
    iss: clientId,
    sub: clientId,
    aud: tokenEndpoint,
    iat: now,
    exp: now + 60,
    jti: randomUUID(),
  };
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const key = createPrivateKey({ key: jwk, format: 'jwk' });
  const signature = createSign('RSA-SHA256').update(signingInput).sign(key);
  return `${signingInput}.${b64u(signature)}`;
}

const privateKeyJwtToken = {
  url: tokenEndpoint,
  async request({ params, provider, checks }: any) {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: params.code as string,
      redirect_uri: provider.callbackUrl,
      client_id: clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: buildClientAssertion(),
    });
    if (checks?.code_verifier) body.set('code_verifier', checks.code_verifier);

    const res = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body,
    });
    const tokens = await res.json();
    if (!res.ok) {
      throw new Error(`Okta token endpoint error: ${tokens.error} ${tokens.error_description ?? ''}`);
    }
    return { tokens };
  },
};

export const authOptions: NextAuthOptions = {
  providers: [
    OktaProvider({
      clientId,
      clientSecret: process.env.OKTA_CLIENT_SECRET || 'placeholder-for-pkce',
      issuer,
      ...(usePrivateKeyJwt ? { token: privateKeyJwtToken } : {}),
    }),
  ],
  pages: {
    signIn: '/auth/signin',
  },
  callbacks: {
    async jwt({ token, account }) {
      if (account) {
        token.accessToken = account.access_token;
        token.idToken = account.id_token;
      }
      return token;
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string;
      session.idToken = token.idToken as string;
      session.user = {
        ...session.user,
        id: token.sub as string,
      };
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
  debug: true,
};
