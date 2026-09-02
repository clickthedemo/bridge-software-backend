import assert from "node:assert/strict";
import test from "node:test";

process.env.NODE_ENV = "test";
process.env.SUPABASE_URL = "https://test-project.supabase.co";
process.env.SUPABASE_ANON_KEY = "test-anon-key";
process.env.CORS_ORIGINS = "http://localhost:3000";
process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service-role-key";
process.env.EMAIL_VERIFICATION_REDIRECT_URL =
    "https://frontend.example.test/login?verified=true";
process.env.PASSWORD_RESET_REDIRECT_URL = "http://localhost:5173/reset-password";

const { buildSessionClaims } = await import("../src/services/session.js");
const { sessionHandler } = await import("../src/routes/v1/session.js");
const { requireAuthentication } = await import(
    "../src/middleware/authentication.js"
);

const userId = "11111111-1111-4111-8111-111111111111";
const organizationId = "22222222-2222-4222-8222-222222222222";
const identity = {
    userId,
    email: "user@example.com",
    accountType: "standard" as const,
    platformRoles: [],
    profile: { displayName: "Miraj Mor", phone: null },
    memberships: [{
        organizationId,
        organizationName: "Example Organization",
        organizationType: "brand" as const,
        role: "owner" as const,
        status: "active" as const
    }]
};

test("missing bearer token returns 401", async () => {
    let status = 0;
    let body: unknown;
    await requireAuthentication(
        { get: () => undefined } as never,
        {
            status(value: number) { status = value; return this; },
            json(value: unknown) { body = value; return this; }
        } as never,
        (() => assert.fail("next must not be called")) as never
    );
    assert.equal(status, 401);
    assert.deepEqual(body, {
        error: "UNAUTHORIZED",
        message: "A valid Bearer access token is required."
    });
});

test("invalid bearer token returns 401", async (context) => {
    const { supabase } = await import("../src/lib/supabase.js");
    context.mock.method(supabase.auth, "getUser", async () => ({
        data: { user: null },
        error: { message: "invalid token" }
    }) as never);
    let status = 0;
    let body: unknown;
    await requireAuthentication(
        { get: () => "Bearer invalid-token" } as never,
        {
            status(value: number) { status = value; return this; },
            json(value: unknown) { body = value; return this; }
        } as never,
        (() => assert.fail("next must not be called")) as never
    );
    assert.equal(status, 401);
    assert.deepEqual(body, {
        error: "UNAUTHORIZED",
        message: "A valid Bearer access token is required."
    });
});

test("normal authenticated identity produces stable session claims", () => {
    assert.deepEqual(buildSessionClaims(identity), {
        userId,
        email: "user@example.com",
        displayName: "Miraj Mor",
        ageEligible: null,
        membershipStatus: "active",
        organizationId,
        organizationVerificationState: "unverified",
        role: "owner",
        delegatedPermissions: [],
        stateLicenseEligibility: null,
        adminScope: null
    });
});

test("user with no organization gets safe none and null tenant claims", () => {
    const claims = buildSessionClaims({ ...identity, memberships: [] });
    assert.equal(claims.membershipStatus, "none");
    assert.equal(claims.organizationId, null);
    assert.equal(claims.role, null);
});

test("multiple memberships do not select an arbitrary tenant", () => {
    const claims = buildSessionClaims({
        ...identity,
        memberships: [
            ...identity.memberships,
            {
                ...identity.memberships[0]!,
                organizationId: "33333333-3333-4333-8333-333333333333",
                role: "admin"
            }
        ]
    });
    assert.equal(claims.membershipStatus, "active");
    assert.equal(claims.organizationId, null);
    assert.equal(claims.role, null);
});

test("platform admin receives platform scope without an organization role", () => {
    const claims = buildSessionClaims({
        ...identity,
        platformRoles: ["admin"],
        memberships: []
    });
    assert.equal(claims.adminScope, "platform");
    assert.equal(claims.role, null);
});

test("organization admin does not become a platform admin", () => {
    const claims = buildSessionClaims({
        ...identity,
        memberships: [{ ...identity.memberships[0]!, role: "admin" }]
    });
    assert.equal(claims.role, "admin");
    assert.equal(claims.adminScope, null);
});

test("session handler returns 200 and excludes sensitive fields", () => {
    let status = 0;
    let body: unknown;
    sessionHandler(
        { identity } as never,
        {
            status(value: number) { status = value; return this; },
            json(value: unknown) { body = value; return this; }
        } as never,
        (() => undefined) as never
    );
    assert.equal(status, 200);
    const serialized = JSON.stringify(body);
    for (const field of [
        "accessToken", "refreshToken", "password", "encryptedEin",
        "raw_user_meta_data", "serviceRole"
    ]) {
        assert.equal(serialized.includes(field), false);
    }
});
