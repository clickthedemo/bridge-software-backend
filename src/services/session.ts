import type { ApplicationIdentity } from "../types/application-identity.js";
import type { SessionClaims } from "../types/session.js";

export const buildSessionClaims = (
    identity: ApplicationIdentity
): SessionClaims => {
    // There is no current/primary organization in the present identity model.
    // A sole active membership is unambiguous; multiple memberships deliberately
    // leave tenant context unset until the frontend supplies an explicit choice.
    const selectedMembership =
        identity.memberships.length === 1
            ? identity.memberships[0]
            : undefined;

    return {
        userId: identity.userId,
        email: identity.email,
        displayName: identity.profile?.displayName ?? null,
        ageEligible: null,
        membershipStatus:
            identity.memberships.length > 0 ? "active" : "none",
        organizationId: selectedMembership?.organizationId ?? null,
        // Verification cases are business-scoped and can be multiple per
        // organization, so there is no reliable organization-level state yet.
        organizationVerificationState: "unverified",
        role: selectedMembership?.role ?? null,
        delegatedPermissions: [],
        stateLicenseEligibility: null,
        adminScope: identity.platformRoles.includes("admin")
            ? "platform"
            : null
    };
};
