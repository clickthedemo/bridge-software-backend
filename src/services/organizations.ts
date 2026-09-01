import { z } from "zod";

import { createUserScopedSupabaseClient } from "../lib/supabase.js";
import type {
    CreateOrganizationInput,
    UpdateOrganizationInput
} from "../schemas/organizations.js";
import type {
    ApplicationIdentity,
    ApplicationMembership,
    OrganizationType
} from "../types/application-identity.js";

const createdOrganizationSchema = z.object({
    organization_id: z.uuid(),
    organization_name: z.string(),
    organization_type: z.enum(["brand", "retailer", "dispensary"]),
    membership_role: z.literal("owner"),
    membership_status: z.literal("active")
});

const organizationRowSchema = z.object({
    id: z.uuid(),
    name: z.string(),
    organization_type: z
        .enum(["brand", "retailer", "dispensary"])
        .nullable()
});

export type OrganizationFailureCode =
    | "ORGANIZATION_NOT_FOUND"
    | "ORGANIZATION_CREATE_FAILED"
    | "ORGANIZATION_UPDATE_FAILED"
    | "INTERNAL_SERVER_ERROR";

export class OrganizationServiceError extends Error {
    constructor(public readonly code: OrganizationFailureCode) {
        super(code);
        this.name = "OrganizationServiceError";
    }
}

export interface OrganizationResponse {
    id: string;
    name: string;
    organizationType: OrganizationType | null;
    membership: {
        role: ApplicationMembership["role"];
        status: ApplicationMembership["status"];
    };
}

const fromMembership = (
    membership: ApplicationMembership
): OrganizationResponse => ({
    id: membership.organizationId,
    name: membership.organizationName,
    organizationType: membership.organizationType,
    membership: {
        role: membership.role,
        status: membership.status
    }
});

export const listOrganizations = (
    identity: ApplicationIdentity
): OrganizationResponse[] => identity.memberships.map(fromMembership);

export const createOrganization = async (
    accessToken: string,
    input: CreateOrganizationInput
): Promise<OrganizationResponse> => {
    const client = createUserScopedSupabaseClient(accessToken);
    const { data, error } = await client
        .rpc("create_organization_with_owner", {
            p_name: input.name,
            p_organization_type: input.organizationType
        })
        .single();

    if (error || !data) {
        throw new OrganizationServiceError("ORGANIZATION_CREATE_FAILED");
    }

    const parsed = createdOrganizationSchema.safeParse(data);

    if (!parsed.success) {
        throw new OrganizationServiceError("INTERNAL_SERVER_ERROR");
    }

    return {
        id: parsed.data.organization_id,
        name: parsed.data.organization_name,
        organizationType: parsed.data.organization_type,
        membership: {
            role: parsed.data.membership_role,
            status: parsed.data.membership_status
        }
    };
};

export const getOrganization = async (
    accessToken: string,
    membership: ApplicationMembership
): Promise<OrganizationResponse> => {
    const client = createUserScopedSupabaseClient(accessToken);
    const { data, error } = await client
        .from("organizations")
        .select("id, name, organization_type")
        .eq("id", membership.organizationId)
        .maybeSingle();

    if (error) {
        throw new OrganizationServiceError("INTERNAL_SERVER_ERROR");
    }

    if (!data) {
        throw new OrganizationServiceError("ORGANIZATION_NOT_FOUND");
    }

    const parsed = organizationRowSchema.safeParse(data);

    if (!parsed.success) {
        throw new OrganizationServiceError("INTERNAL_SERVER_ERROR");
    }

    return {
        id: parsed.data.id,
        name: parsed.data.name,
        organizationType: parsed.data.organization_type,
        membership: {
            role: membership.role,
            status: membership.status
        }
    };
};

export const updateOrganization = async (
    accessToken: string,
    membership: ApplicationMembership,
    input: UpdateOrganizationInput
): Promise<OrganizationResponse> => {
    const client = createUserScopedSupabaseClient(accessToken);
    const changes: {
        name?: string;
        organization_type?: OrganizationType;
    } = {};

    if (input.name !== undefined) {
        changes.name = input.name;
    }
    if (input.organizationType !== undefined) {
        changes.organization_type = input.organizationType;
    }

    const { data, error } = await client
        .from("organizations")
        .update(changes)
        .eq("id", membership.organizationId)
        .select("id, name, organization_type")
        .maybeSingle();

    if (error) {
        throw new OrganizationServiceError("ORGANIZATION_UPDATE_FAILED");
    }

    if (!data) {
        throw new OrganizationServiceError("ORGANIZATION_NOT_FOUND");
    }

    const parsed = organizationRowSchema.safeParse(data);

    if (!parsed.success) {
        throw new OrganizationServiceError("INTERNAL_SERVER_ERROR");
    }

    return {
        id: parsed.data.id,
        name: parsed.data.name,
        organizationType: parsed.data.organization_type,
        membership: {
            role: membership.role,
            status: membership.status
        }
    };
};
