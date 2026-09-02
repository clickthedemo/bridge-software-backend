import assert from "node:assert/strict";
import test from "node:test";
import type { User } from "@supabase/supabase-js";

process.env.NODE_ENV = "test";
process.env.SUPABASE_URL = "https://test-project.supabase.co";
process.env.SUPABASE_ANON_KEY = "test-anon-key";
process.env.CORS_ORIGINS = "http://localhost:3000";
process.env.SUPABASE_SERVICE_ROLE_KEY = "test-service-role-key";
process.env.EMAIL_VERIFICATION_REDIRECT_URL =
    "https://frontend.example.test/login?verified=true";
process.env.PASSWORD_RESET_REDIRECT_URL = "http://localhost:5173/reset-password";

const { adminUsersQuerySchema } = await import(
    "../src/schemas/admin-users.js"
);
const { combineAdminUserData } = await import(
    "../src/services/admin-users.js"
);
const { hasPermission, requirePermission } = await import(
    "../src/middleware/authorization.js"
);
const { createListAdminUsersHandler } = await import(
    "../src/routes/v1/admin-verification.js"
);

const userId = "11111111-1111-4111-8111-111111111111";
const organizationOne = "22222222-2222-4222-8222-222222222222";
const organizationTwo = "33333333-3333-4333-8333-333333333333";

const baseIdentity = {
    userId,
    email: "member@example.com",
    accountType: "standard" as const,
    platformRoles: [],
    profile: { displayName: "Member", phone: null },
    memberships: []
};

test("admin users query defaults and bounded pagination", () => {
    assert.deepEqual(adminUsersQuerySchema.parse({}), { page: 1, pageSize: 50 });
    assert.deepEqual(adminUsersQuerySchema.parse({ page: "2", pageSize: "100" }), {
        page: 2,
        pageSize: 100
    });
    assert.equal(adminUsersQuerySchema.safeParse({ pageSize: "101" }).success, false);
});

test("admin user permission rejects members and organization owners", () => {
    assert.equal(hasPermission(baseIdentity, "admin:users_read"), false);
    assert.equal(
        hasPermission(
            {
                ...baseIdentity,
                memberships: [{
                    organizationId: organizationOne,
                    organizationName: "One",
                    organizationType: "brand" as const,
                    role: "owner" as const,
                    status: "active" as const
                }]
            },
            "admin:users_read"
        ),
        false
    );
});

test("admin user permission allows only platform admins", () => {
    assert.equal(
        hasPermission(
            { ...baseIdentity, platformRoles: ["admin"] },
            "admin:users_read"
        ),
        true
    );
});

test("admin permission middleware returns 401 without authentication", () => {
    let status = 0;
    let body: unknown;
    const response = {
        status(value: number) { status = value; return this; },
        json(value: unknown) { body = value; return this; }
    };
    requirePermission("admin:users_read")(
        {} as never,
        response as never,
        (() => assert.fail("next must not be called")) as never
    );
    assert.equal(status, 401);
    assert.deepEqual(body, {
        error: "UNAUTHORIZED",
        message: "A valid Bearer access token is required."
    });
});

test("admin permission middleware returns 403 for an organization owner", () => {
    let status = 0;
    const response = {
        status(value: number) { status = value; return this; },
        json() { return this; }
    };
    requirePermission("admin:users_read")(
        {
            authentication: { user: { id: userId } },
            identity: {
                ...baseIdentity,
                memberships: [{
                    organizationId: organizationOne,
                    organizationName: "One",
                    organizationType: "brand",
                    role: "owner",
                    status: "active"
                }]
            }
        } as never,
        response as never,
        (() => assert.fail("next must not be called")) as never
    );
    assert.equal(status, 403);
});

test("platform admin authorization and list handler produce HTTP 200", async () => {
    let authorized = false;
    requirePermission("admin:users_read")(
        {
            authentication: { user: { id: userId } },
            identity: { ...baseIdentity, platformRoles: ["admin"] }
        } as never,
        {} as never,
        (() => { authorized = true; }) as never
    );
    assert.equal(authorized, true);

    let status = 0;
    let body: unknown;
    const expected = {
        users: [],
        pagination: { page: 1, pageSize: 50, total: 0 }
    };
    const handler = createListAdminUsersHandler(async () => expected);
    await handler(
        {} as never,
        {
            locals: { adminUsersQuery: { page: 1, pageSize: 50 } },
            status(value: number) { status = value; return this; },
            json(value: unknown) { body = value; return this; }
        } as never,
        (() => undefined) as never
    );
    assert.equal(status, 200);
    assert.deepEqual(body, expected);
});

test("safe projection combines profile and auth state without duplicate users", () => {
    const authUser = {
        id: userId,
        email: "user@example.com",
        email_confirmed_at: "2026-09-02T10:00:00.000Z",
        created_at: "2026-09-01T10:00:00.000Z",
        last_sign_in_at: "2026-09-02T11:00:00.000Z",
        encrypted_password: "must-not-leak",
        confirmation_token: "must-not-leak-too"
    } as unknown as User;

    const users = combineAdminUserData(
        [authUser],
        [{ id: userId, display_name: "Miraj Mor", account_type: "sales_rep" }],
        [{ user_id: userId, role: "admin" }],
        [
            {
                user_id: userId,
                organization_id: organizationOne,
                role: "owner",
                status: "active",
                organizations: { id: organizationOne, name: "One" }
            },
            {
                user_id: userId,
                organization_id: organizationTwo,
                role: "reviewer",
                status: "active",
                organizations: { id: organizationTwo, name: "Two" }
            }
        ]
    );

    assert.equal(users.length, 1);
    assert.equal(users[0]?.displayName, "Miraj Mor");
    assert.equal(users[0]?.emailVerified, true);
    assert.equal(users[0]?.organizationMemberships.length, 2);
    const serialized = JSON.stringify(users);
    assert.equal(serialized.includes("encrypted_password"), false);
    assert.equal(serialized.includes("confirmation_token"), false);
    assert.equal(serialized.includes("must-not-leak"), false);
});
