import assert from "node:assert/strict";
import test from "node:test";

process.env.NODE_ENV = "test";
process.env.SUPABASE_URL = "https://test-project.supabase.co";
process.env.SUPABASE_ANON_KEY = "test-anon-key";
process.env.CORS_ORIGINS = "http://localhost:3000";
process.env.EMAIL_VERIFICATION_REDIRECT_URL =
    "https://frontend.example.test/login?verified=true";
process.env.PASSWORD_RESET_REDIRECT_URL = "http://localhost:5173/reset-password";

const { registrationSchema } = await import(
    "../src/schemas/authentication.js"
);
const {
    buildRegistrationCredentials,
    buildResendVerificationCredentials,
    classifySupabaseAuthFailure
} = await import("../src/services/authentication.js");
const { authFailureStatus } = await import("../src/routes/v1/auth.js");
const { createLoginHandler, createLogoutHandler } = await import(
    "../src/routes/v1/auth.js"
);
const {
    ACCESS_TOKEN_COOKIE,
    REFRESH_TOKEN_COOKIE,
    getCookieSecurity
} = await import("../src/http/auth-cookies.js");

test("registration rate limits retain HTTP 429 semantics", () => {
    const error = classifySupabaseAuthFailure(
        "register",
        { code: "over_email_send_rate_limit", status: 429 },
        "AUTH_REGISTRATION_FAILED"
    );
    assert.equal(error.code, "AUTH_RATE_LIMITED");
    assert.equal(error.providerStatus, 429);
    assert.equal(authFailureStatus(error), 429);
});

test("unverified login is distinguished by provider code", () => {
    const error = classifySupabaseAuthFailure(
        "login",
        { code: "email_not_confirmed", status: 400 },
        "AUTH_LOGIN_FAILED"
    );
    assert.equal(error.code, "EMAIL_NOT_VERIFIED");
    assert.equal(authFailureStatus(error), 403);
});

test("other login rejections remain non-enumerating", () => {
    for (const code of ["invalid_credentials", "user_not_found"]) {
        const error = classifySupabaseAuthFailure(
            "login",
            { code, status: 400 },
            "AUTH_LOGIN_FAILED"
        );
        assert.equal(error.code, "INVALID_CREDENTIALS");
        assert.equal(authFailureStatus(error), 401);
    }
});

test("registration accepts and normalizes displayName", () => {
    const input = registrationSchema.parse({
        email: "USER@example.com",
        password: "ExamplePassword123!",
        displayName: "  Miraj Mor  "
    });
    assert.equal(input.email, "user@example.com");
    assert.equal(input.displayName, "Miraj Mor");
    assert.deepEqual(buildRegistrationCredentials(input).options, {
        emailRedirectTo: "https://frontend.example.test/login?verified=true",
        data: { display_name: "Miraj Mor" }
    });
});

test("registration remains valid without displayName", () => {
    const input = registrationSchema.parse({
        email: "user@example.com",
        password: "ExamplePassword123!"
    });
    assert.equal(input.displayName, undefined);
    assert.deepEqual(buildRegistrationCredentials(input).options, {
        emailRedirectTo: "https://frontend.example.test/login?verified=true"
    });
});

test("resend verification uses the configured email redirect", () => {
    assert.deepEqual(
        buildResendVerificationCredentials({ email: "user@example.com" }),
        {
            type: "signup",
            email: "user@example.com",
            options: {
                emailRedirectTo:
                    "https://frontend.example.test/login?verified=true"
            }
        }
    );
});

test("successful login issues HttpOnly cookie credentials and preserves token response", async () => {
    const result = {
        accessToken: "access-secret",
        refreshToken: "refresh-secret",
        expiresAt: 1234,
        expiresIn: 3600,
        tokenType: "bearer",
        user: { id: "11111111-1111-4111-8111-111111111111", email: "user@example.com" }
    };
    const cookies: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];
    let body: unknown;
    await createLoginHandler(async () => result)(
        { body: { email: "user@example.com", password: "secret" } } as never,
        {
            cookie(name: string, value: string, options: Record<string, unknown>) {
                cookies.push({ name, value, options }); return this;
            },
            status() { return this; },
            json(value: unknown) { body = value; return this; }
        } as never,
        (() => undefined) as never
    );
    assert.deepEqual(body, result);
    assert.deepEqual(cookies.map(({ name }) => name), [
        ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
    ]);
    for (const cookie of cookies) {
        assert.equal(cookie.options.httpOnly, true);
        assert.equal(cookie.options.path, "/api/v1");
        assert.equal(cookie.options.sameSite, "lax");
        assert.equal(cookie.options.secure, false);
    }
    assert.equal(cookies[0]?.options.maxAge, 3_600_000);
    assert.equal("maxAge" in cookies[1]!.options, false);
});

test("production cookie transport is Secure and SameSite=None", () => {
    assert.deepEqual(getCookieSecurity("production"), {
        secure: true,
        sameSite: "none"
    });
});

test("logout clears both cookies with matching attributes and revokes provider session", async () => {
    const cleared: Array<{ name: string; options: Record<string, unknown> }> = [];
    let revoked: unknown[] = [];
    let status = 0;
    await createLogoutHandler(async (...tokens) => { revoked = tokens; })(
        {
            get(name: string) {
                return name === "cookie"
                    ? `${ACCESS_TOKEN_COOKIE}=access; ${REFRESH_TOKEN_COOKIE}=refresh`
                    : undefined;
            }
        } as never,
        {
            clearCookie(name: string, options: Record<string, unknown>) {
                cleared.push({ name, options }); return this;
            },
            status(value: number) { status = value; return this; },
            send() { return this; }
        } as never,
        (() => undefined) as never
    );
    assert.equal(status, 204);
    assert.deepEqual(revoked, ["access", "refresh"]);
    assert.deepEqual(cleared.map(({ name }) => name), [
        ACCESS_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE
    ]);
    for (const cookie of cleared) assert.equal(cookie.options.path, "/api/v1");
});
