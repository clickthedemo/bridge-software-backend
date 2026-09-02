import assert from "node:assert/strict";
import test from "node:test";

process.env.NODE_ENV = "test";
process.env.SUPABASE_URL = "https://test-project.supabase.co";
process.env.SUPABASE_ANON_KEY = "test-anon-key";
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
