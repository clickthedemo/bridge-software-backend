import { z } from "zod";
import { randomUUID } from "node:crypto";

import {
    createAdminSupabaseClient,
    createPublicSupabaseClient,
    createUserScopedSupabaseClient,
    SupabaseAdminNotConfiguredError
} from "../lib/supabase.js";
import type {
    DirectoryProfileReviewReasonInput,
    DirectoryProfileLogoUploadInput,
    PublicDirectoryProfilesQuery,
    PutDirectoryProfileInput
} from "../schemas/directory-profiles.js";

const directoryProfileStatusSchema = z.enum([
    "draft",
    "pending_review",
    "correction_requested",
    "approved",
    "rejected",
    "suspended"
]);

const protectedProfileRowSchema = z.object({
    id: z.uuid(),
    organization_id: z.uuid(),
    business_id: z.uuid(),
    slug: z.string(),
    display_name: z.string(),
    summary: z.string().nullable(),
    website_url: z.string().nullable(),
    logo_storage_path: z.string().nullable(),
    status: directoryProfileStatusSchema,
    submitted_at: z.string().nullable(),
    reviewed_at: z.string().nullable(),
    workflow_reason: z.string().nullable(),
    published_version_id: z.uuid().nullable(),
    approved_at: z.string().nullable(),
    created_at: z.string(),
    updated_at: z.string(),
    businesses: z.object({
        id: z.uuid(),
        legal_name: z.string(),
        dba_name: z.string().nullable(),
        status: z.enum(["active", "inactive", "archived"])
    })
});

const publicProfileRowSchema = z.object({
    slug: z.string(),
    display_name: z.string(),
    summary: z.string().nullable(),
    website_url: z.string().nullable(),
    business_name: z.string(),
    verified: z.literal(true),
    has_logo: z.boolean()
});

const publicProfileListRowSchema = publicProfileRowSchema.extend({
    cursor_name: z.string()
});

const reviewResultSchema = z.object({
    profile_id: z.uuid(),
    status: directoryProfileStatusSchema,
    published_version_id: z.uuid().nullable(),
    reviewed_at: z.string()
});

export type DirectoryProfileFailureCode =
    | "DIRECTORY_PROFILE_NOT_FOUND"
    | "DIRECTORY_PROFILE_BUSINESS_MISMATCH"
    | "DIRECTORY_PROFILE_BUSINESS_CHANGE_REQUIRES_REAPPROVAL"
    | "DIRECTORY_PROFILE_SLUG_CONFLICT"
    | "DIRECTORY_PROFILE_INVALID_STATE"
    | "DIRECTORY_PROFILE_VERIFICATION_REQUIRED"
    | "DIRECTORY_PROFILE_SELF_REVIEW_FORBIDDEN"
    | "DIRECTORY_PROFILE_REVIEW_UNAVAILABLE"
    | "DIRECTORY_PROFILE_INVALID_CURSOR"
    | "DIRECTORY_PROFILE_MEDIA_UNAVAILABLE"
    | "DIRECTORY_PROFILE_READ_FAILED"
    | "DIRECTORY_PROFILE_WRITE_FAILED"
    | "INTERNAL_SERVER_ERROR";

export class DirectoryProfileServiceError extends Error {
    constructor(public readonly code: DirectoryProfileFailureCode) {
        super(code);
        this.name = "DirectoryProfileServiceError";
    }
}

export interface ProtectedDirectoryProfileResponse {
    id: string;
    organizationId: string;
    businessId: string;
    slug: string;
    displayName: string;
    summary: string | null;
    websiteUrl: string | null;
    logoUrl: string | null;
    status: z.infer<typeof directoryProfileStatusSchema>;
    hasPublishedVersion: boolean;
    submittedAt: string | null;
    reviewedAt: string | null;
    workflowReason: string | null;
    approvedAt: string | null;
    createdAt: string;
    updatedAt: string;
    business: {
        id: string;
        legalName: string;
        dbaName: string | null;
        status: "active" | "inactive" | "archived";
    };
}

export interface PublicDirectoryProfileResponse {
    slug: string;
    displayName: string;
    summary: string | null;
    websiteUrl: string | null;
    businessName: string;
    verified: true;
    logoUrl: string | null;
}

export interface PublicDirectoryProfilesResponse {
    profiles: PublicDirectoryProfileResponse[];
    pageInfo: {
        nextCursor: string | null;
        hasMore: boolean;
    };
}

export type DirectoryProfileReviewAction =
    | "approve"
    | "request_correction"
    | "reject"
    | "suspend";

export interface DirectoryProfileReviewResponse {
    profileId: string;
    status: z.infer<typeof directoryProfileStatusSchema>;
    hasPublishedVersion: boolean;
    reviewedAt: string;
}

export const projectProtectedDirectoryProfile = (
    row: unknown
): ProtectedDirectoryProfileResponse => {
    const parsed = protectedProfileRowSchema.safeParse(row);
    if (!parsed.success) {
        throw new DirectoryProfileServiceError("INTERNAL_SERVER_ERROR");
    }

    return {
        id: parsed.data.id,
        organizationId: parsed.data.organization_id,
        businessId: parsed.data.business_id,
        slug: parsed.data.slug,
        displayName: parsed.data.display_name,
        summary: parsed.data.summary,
        websiteUrl: parsed.data.website_url,
        logoUrl: parsed.data.logo_storage_path
            ? `/api/v1/organizations/${parsed.data.organization_id}/directory-profile/logo`
            : null,
        status: parsed.data.status,
        hasPublishedVersion: parsed.data.published_version_id !== null,
        submittedAt: parsed.data.submitted_at,
        reviewedAt: parsed.data.reviewed_at,
        workflowReason: parsed.data.workflow_reason,
        approvedAt: parsed.data.approved_at,
        createdAt: parsed.data.created_at,
        updatedAt: parsed.data.updated_at,
        business: {
            id: parsed.data.businesses.id,
            legalName: parsed.data.businesses.legal_name,
            dbaName: parsed.data.businesses.dba_name,
            status: parsed.data.businesses.status
        }
    };
};

export const projectPublicDirectoryProfile = (
    row: unknown
): PublicDirectoryProfileResponse => {
    const parsed = publicProfileRowSchema.safeParse(row);
    if (!parsed.success) {
        throw new DirectoryProfileServiceError("INTERNAL_SERVER_ERROR");
    }

    return {
        slug: parsed.data.slug,
        displayName: parsed.data.display_name,
        summary: parsed.data.summary,
        websiteUrl: parsed.data.website_url,
        businessName: parsed.data.business_name,
        verified: parsed.data.verified,
        logoUrl: parsed.data.has_logo
            ? `/api/v1/directory/profiles/${encodeURIComponent(parsed.data.slug)}/logo`
            : null
    };
};

const protectedProfileColumns = [
    "id",
    "organization_id",
    "business_id",
    "slug",
    "display_name",
    "summary",
    "website_url",
    "logo_storage_path",
    "status",
    "submitted_at",
    "reviewed_at",
    "workflow_reason",
    "published_version_id",
    "approved_at",
    "created_at",
    "updated_at",
    "businesses!inner(id, legal_name, dba_name, status)"
].join(", ");

export const getDirectoryProfile = async (
    accessToken: string,
    organizationId: string
): Promise<ProtectedDirectoryProfileResponse> => {
    const client = createUserScopedSupabaseClient(accessToken);
    const { data, error } = await client
        .from("directory_profiles")
        .select(protectedProfileColumns)
        .eq("organization_id", organizationId)
        .maybeSingle();

    if (error) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_READ_FAILED");
    }
    if (!data) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_NOT_FOUND");
    }

    return projectProtectedDirectoryProfile(data);
};

const mapWriteError = (code: string | undefined): never => {
    if (code === "23503") {
        throw new DirectoryProfileServiceError(
            "DIRECTORY_PROFILE_BUSINESS_MISMATCH"
        );
    }
    if (code === "23505") {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_SLUG_CONFLICT");
    }
    if (code === "55000") {
        throw new DirectoryProfileServiceError(
            "DIRECTORY_PROFILE_BUSINESS_CHANGE_REQUIRES_REAPPROVAL"
        );
    }
    throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_WRITE_FAILED");
};

export const putDirectoryProfile = async (
    accessToken: string,
    organizationId: string,
    input: PutDirectoryProfileInput
): Promise<ProtectedDirectoryProfileResponse> => {
    const client = createUserScopedSupabaseClient(accessToken);
    const { error } = await client.rpc("upsert_directory_profile", {
        p_organization_id: organizationId,
        p_business_id: input.businessId,
        p_slug: input.slug,
        p_display_name: input.displayName,
        p_summary: input.summary ?? null,
        p_website_url: input.websiteUrl ?? null
    });

    if (error) {
        return mapWriteError(error.code);
    }

    return getDirectoryProfile(accessToken, organizationId);
};

export const submitDirectoryProfile = async (
    accessToken: string,
    organizationId: string
): Promise<ProtectedDirectoryProfileResponse> => {
    const client = createUserScopedSupabaseClient(accessToken);
    const { error } = await client.rpc("submit_directory_profile", {
        p_organization_id: organizationId
    });

    if (error) {
        if (error.code === "P0002") {
            throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_NOT_FOUND");
        }
        if (error.code === "55000" || error.code === "23514") {
            throw new DirectoryProfileServiceError(
                "DIRECTORY_PROFILE_INVALID_STATE"
            );
        }
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_WRITE_FAILED");
    }

    return getDirectoryProfile(accessToken, organizationId);
};

export const getPublicDirectoryProfile = async (
    slug: string
): Promise<PublicDirectoryProfileResponse> => {
    const client = createPublicSupabaseClient();
    const { data, error } = await client
        .rpc("get_public_directory_profile", { p_slug: slug })
        .maybeSingle();

    if (error) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_READ_FAILED");
    }
    if (!data) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_NOT_FOUND");
    }

    return projectPublicDirectoryProfile(data);
};

const logoExtensionByContentType: Record<
    DirectoryProfileLogoUploadInput["contentType"],
    string
> = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp"
};

export interface DirectoryProfileLogoUploadResponse {
    signedUrl: string;
    expiresInSeconds: 7200;
}

export const createDirectoryProfileLogoUpload = async (
    accessToken: string,
    organizationId: string,
    input: DirectoryProfileLogoUploadInput
): Promise<DirectoryProfileLogoUploadResponse> => {
    const profile = await getDirectoryProfile(accessToken, organizationId);
    const extension = logoExtensionByContentType[input.contentType];
    const path = `${organizationId}/${profile.id}/logo/${randomUUID()}.${extension}`;
    const admin = getAdminClient();
    const { data, error } = await admin.storage
        .from("directory-media")
        .createSignedUploadUrl(path);

    if (error || !data?.signedUrl) {
        throw new DirectoryProfileServiceError(
            "DIRECTORY_PROFILE_MEDIA_UNAVAILABLE"
        );
    }

    const client = createUserScopedSupabaseClient(accessToken);
    const { error: updateError } = await client.rpc("set_directory_profile_logo", {
        p_organization_id: organizationId,
        p_logo_storage_path: path
    });
    if (updateError) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_WRITE_FAILED");
    }

    return { signedUrl: data.signedUrl, expiresInSeconds: 7200 };
};

export const deleteDirectoryProfileLogo = async (
    accessToken: string,
    organizationId: string
): Promise<ProtectedDirectoryProfileResponse> => {
    const client = createUserScopedSupabaseClient(accessToken);
    const { error } = await client.rpc("set_directory_profile_logo", {
        p_organization_id: organizationId,
        p_logo_storage_path: null
    });
    if (error) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_WRITE_FAILED");
    }
    return getDirectoryProfile(accessToken, organizationId);
};

const publicLogoPathRowSchema = z.object({ logo_storage_path: z.string() });

export const getPublicDirectoryProfileLogoUrl = async (
    slug: string
): Promise<string> => {
    const admin = getAdminClient();
    const { data, error } = await admin
        .rpc("get_public_directory_profile_logo_path", { p_slug: slug })
        .maybeSingle();
    if (error || !data) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_NOT_FOUND");
    }
    const parsed = publicLogoPathRowSchema.safeParse(data);
    if (!parsed.success) {
        throw new DirectoryProfileServiceError("INTERNAL_SERVER_ERROR");
    }
    const signed = await admin.storage
        .from("directory-media")
        .createSignedUrl(parsed.data.logo_storage_path, 300);
    if (signed.error || !signed.data?.signedUrl) {
        throw new DirectoryProfileServiceError(
            "DIRECTORY_PROFILE_MEDIA_UNAVAILABLE"
        );
    }
    return signed.data.signedUrl;
};

export const getProtectedDirectoryProfileLogoUrl = async (
    accessToken: string,
    organizationId: string
): Promise<string> => {
    const profile = await getDirectoryProfile(accessToken, organizationId);
    if (!profile.logoUrl) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_NOT_FOUND");
    }
    const client = createUserScopedSupabaseClient(accessToken);
    const { data, error } = await client.rpc("get_directory_profile_logo_path", {
        p_organization_id: organizationId
    }).maybeSingle();
    if (error || !data) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_NOT_FOUND");
    }
    const parsed = publicLogoPathRowSchema.safeParse(data);
    if (!parsed.success) {
        throw new DirectoryProfileServiceError("INTERNAL_SERVER_ERROR");
    }
    const signed = await getAdminClient().storage
        .from("directory-media")
        .createSignedUrl(parsed.data.logo_storage_path, 300);
    if (signed.error || !signed.data?.signedUrl) {
        throw new DirectoryProfileServiceError(
            "DIRECTORY_PROFILE_MEDIA_UNAVAILABLE"
        );
    }
    return signed.data.signedUrl;
};

const directoryCursorSchema = z.object({
    sort: z.enum(["name_asc", "name_desc"]),
    name: z.string(),
    slug: z.string()
});

const encodeDirectoryCursor = (
    sort: PublicDirectoryProfilesQuery["sort"],
    name: string,
    slug: string
): string => Buffer.from(JSON.stringify({ sort, name, slug }), "utf8")
    .toString("base64url");

export const decodeDirectoryCursor = (
    cursor: string | undefined,
    sort: PublicDirectoryProfilesQuery["sort"]
): z.infer<typeof directoryCursorSchema> | null => {
    if (!cursor) return null;

    try {
        const decoded = directoryCursorSchema.parse(
            JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"))
        );
        if (decoded.sort !== sort) throw new Error("Cursor sort mismatch");
        return decoded;
    } catch {
        throw new DirectoryProfileServiceError(
            "DIRECTORY_PROFILE_INVALID_CURSOR"
        );
    }
};

export const projectPublicDirectoryProfilesPage = (
    rows: unknown,
    query: Pick<PublicDirectoryProfilesQuery, "sort" | "limit">
): PublicDirectoryProfilesResponse => {
    const parsed = z.array(publicProfileListRowSchema).safeParse(rows);
    if (!parsed.success) {
        throw new DirectoryProfileServiceError("INTERNAL_SERVER_ERROR");
    }

    const hasMore = parsed.data.length > query.limit;
    const page = parsed.data.slice(0, query.limit);
    const last = page.at(-1);

    return {
        profiles: page.map(projectPublicDirectoryProfile),
        pageInfo: {
            hasMore,
            nextCursor: hasMore && last
                ? encodeDirectoryCursor(query.sort, last.cursor_name, last.slug)
                : null
        }
    };
};

export const listPublicDirectoryProfiles = async (
    query: PublicDirectoryProfilesQuery
): Promise<PublicDirectoryProfilesResponse> => {
    const cursor = decodeDirectoryCursor(query.cursor, query.sort);
    const client = createPublicSupabaseClient();
    const { data, error } = await client.rpc("list_public_directory_profiles", {
        p_query: query.q || null,
        p_organization_type: query.organizationType ?? null,
        p_sort: query.sort,
        p_cursor_name: cursor?.name ?? null,
        p_cursor_slug: cursor?.slug ?? null,
        p_limit: query.limit + 1
    });

    if (error) {
        throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_READ_FAILED");
    }

    return projectPublicDirectoryProfilesPage(data ?? [], query);
};

const getAdminClient = () => {
    try {
        return createAdminSupabaseClient();
    } catch (error) {
        if (error instanceof SupabaseAdminNotConfiguredError) {
            throw new DirectoryProfileServiceError(
                "DIRECTORY_PROFILE_REVIEW_UNAVAILABLE"
            );
        }
        throw new DirectoryProfileServiceError("INTERNAL_SERVER_ERROR");
    }
};

export const reviewDirectoryProfile = async (
    actorUserId: string,
    profileId: string,
    action: DirectoryProfileReviewAction,
    input?: DirectoryProfileReviewReasonInput
): Promise<DirectoryProfileReviewResponse> => {
    const { data, error } = await getAdminClient()
        .rpc("review_directory_profile", {
            p_actor_user_id: actorUserId,
            p_profile_id: profileId,
            p_action: action,
            p_reason: input?.reason ?? null
        })
        .single();

    if (error) {
        if (error.code === "P0002") {
            throw new DirectoryProfileServiceError("DIRECTORY_PROFILE_NOT_FOUND");
        }
        if (error.code === "42501") {
            throw new DirectoryProfileServiceError(
                "DIRECTORY_PROFILE_SELF_REVIEW_FORBIDDEN"
            );
        }
        if (error.code === "55000") {
            throw new DirectoryProfileServiceError(
                error.message.includes("eligibility")
                    ? "DIRECTORY_PROFILE_VERIFICATION_REQUIRED"
                    : "DIRECTORY_PROFILE_INVALID_STATE"
            );
        }
        if (error.code === "23505") {
            throw new DirectoryProfileServiceError(
                "DIRECTORY_PROFILE_SLUG_CONFLICT"
            );
        }
        throw new DirectoryProfileServiceError(
            "DIRECTORY_PROFILE_REVIEW_UNAVAILABLE"
        );
    }

    const parsed = reviewResultSchema.safeParse(data);
    if (!parsed.success) {
        throw new DirectoryProfileServiceError("INTERNAL_SERVER_ERROR");
    }

    return {
        profileId: parsed.data.profile_id,
        status: parsed.data.status,
        hasPublishedVersion: parsed.data.published_version_id !== null,
        reviewedAt: parsed.data.reviewed_at
    };
};
