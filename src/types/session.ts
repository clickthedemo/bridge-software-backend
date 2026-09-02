import type { OrganizationRole } from "./application-identity.js";

export type SessionMembershipStatus =
    | "none"
    | "pending"
    | "active"
    | "suspended";

export type OrganizationVerificationState =
    | "unverified"
    | "pending"
    | "verified"
    | "changes_requested"
    | "rejected";

export interface SessionClaims {
    userId: string;
    email: string | null;
    displayName: string | null;
    ageEligible: boolean | null;
    membershipStatus: SessionMembershipStatus;
    organizationId: string | null;
    organizationVerificationState: OrganizationVerificationState;
    role: OrganizationRole | null;
    delegatedPermissions: string[];
    stateLicenseEligibility: boolean | null;
    adminScope: "platform" | null;
}
