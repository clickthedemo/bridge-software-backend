import { z } from "zod";

import {
    createAdminSupabaseClient,
    SupabaseAdminNotConfiguredError
} from "../lib/supabase.js";
import {
    verificationCaseStatusSchema,
    verificationItemStatusSchema,
    verificationItemTypeSchema,
    type AdminVerificationQueueQuery,
    type AdminVerificationReviewInput
} from "../schemas/admin-verification.js";

const nullableTimestamp = z.string().nullable();
const verificationMethodSchema = z.enum(["manual", "api"]).nullable();

const queueRowSchema = z.object({
    verification_case_id: z.uuid(),
    verification_item_id: z.uuid(),
    organization_id: z.uuid(),
    organization_name: z.string(),
    business_id: z.uuid(),
    business_legal_name: z.string(),
    item_type: verificationItemTypeSchema,
    item_status: verificationItemStatusSchema,
    verification_method: verificationMethodSchema,
    case_created_at: z.string(),
    case_submitted_at: nullableTimestamp,
    item_created_at: z.string(),
    item_updated_at: z.string(),
    item_reviewed_at: nullableTimestamp
});

const historySchema = z.object({
    id: z.uuid(),
    previous_status: verificationItemStatusSchema.nullable(),
    new_status: verificationItemStatusSchema.nullable(),
    action: z.enum([
        "created",
        "status_changed",
        "review_started",
        "approved",
        "rejected",
        "correction_requested",
        "verification_requested",
        "verification_completed",
        "note_added"
    ]),
    reason: z.string().nullable(),
    notes: z.string().nullable(),
    actor_user_id: z.uuid().nullable(),
    created_at: z.string()
});

const documentSchema = z.object({
    id: z.uuid(),
    document_type: z.enum([
        "ein",
        "cannabis_license",
        "business_registration",
        "other"
    ]),
    file_name: z.string(),
    mime_type: z.string().nullable(),
    file_size_bytes: z.union([z.number(), z.string()]).nullable(),
    uploaded_by_user_id: z.uuid(),
    uploaded_at: z.string(),
    review_status: z.enum([
        "pending",
        "approved",
        "rejected",
        "correction_required"
    ]),
    reviewed_by_user_id: z.uuid().nullable(),
    reviewed_at: nullableTimestamp,
    review_notes: z.string().nullable()
});

const providerAttemptSchema = z.object({
    id: z.uuid(),
    provider: z.string(),
    provider_reference: z.string().nullable(),
    result_status: z.string().nullable(),
    result_reason: z.string().nullable(),
    requested_at: z.string(),
    completed_at: nullableTimestamp
});

const cannabisLicenseVerificationSchema = z.object({
    id: z.uuid(),
    state_code: z.string(),
    license_number: z.string(),
    registry_name: z.string().nullable(),
    registry_url: z.string().nullable(),
    looked_up_by_user_id: z.uuid(),
    looked_up_at: z.string(),
    result_status: z.string().nullable(),
    result_notes: z.string().nullable()
});

const caseDetailSchema = z.object({
    verification_case_id: z.uuid(),
    status: verificationCaseStatusSchema,
    submitted_at: nullableTimestamp,
    started_review_at: nullableTimestamp,
    completed_at: nullableTimestamp,
    created_at: z.string(),
    updated_at: z.string(),
    organization: z.object({
        id: z.uuid(),
        name: z.string(),
        organization_type: z.enum(["brand", "retailer", "dispensary"]).nullable()
    }),
    business: z.object({
        id: z.uuid(),
        legal_name: z.string(),
        dba_name: z.string().nullable(),
        ein_last_four: z.string().regex(/^[0-9]{4}$/).nullable(),
        cannabis_license_number: z.string().nullable(),
        cannabis_license_state: z.string().nullable()
    }),
    items: z.array(z.object({
        id: z.uuid(),
        item_type: verificationItemTypeSchema,
        status: verificationItemStatusSchema,
        verification_method: verificationMethodSchema,
        reviewed_by_user_id: z.uuid().nullable(),
        reviewed_at: nullableTimestamp,
        rejection_reason: z.string().nullable(),
        correction_notes: z.string().nullable(),
        created_at: z.string(),
        updated_at: z.string(),
        history: z.array(historySchema),
        documents: z.array(documentSchema),
        ein_verification_attempts: z.array(providerAttemptSchema),
        cannabis_license_verifications: z.array(
            cannabisLicenseVerificationSchema
        )
    }))
});

const reviewResultSchema = z.object({
    verification_item_id: z.uuid(),
    verification_case_id: z.uuid(),
    organization_id: z.uuid(),
    previous_status: verificationItemStatusSchema,
    new_status: z.enum(["verified", "rejected", "correction_required"]),
    reviewed_by_user_id: z.uuid(),
    reviewed_at: z.string()
});

export type AdminVerificationFailureCode =
    | "FORBIDDEN"
    | "VERIFICATION_CASE_NOT_FOUND"
    | "VERIFICATION_ITEM_NOT_FOUND"
    | "VERIFICATION_INVALID_STATE"
    | "ADMIN_VERIFICATION_UNAVAILABLE"
    | "INTERNAL_SERVER_ERROR";

export class AdminVerificationServiceError extends Error {
    constructor(public readonly code: AdminVerificationFailureCode) {
        super(code);
        this.name = "AdminVerificationServiceError";
    }
}

const getAdminClient = () => {
    try {
        return createAdminSupabaseClient();
    } catch (error) {
        if (error instanceof SupabaseAdminNotConfiguredError) {
            throw new AdminVerificationServiceError(
                "ADMIN_VERIFICATION_UNAVAILABLE"
            );
        }
        throw new AdminVerificationServiceError("INTERNAL_SERVER_ERROR");
    }
};

const mapRpcError = (
    code: string | undefined,
    notFoundCode?: "VERIFICATION_CASE_NOT_FOUND" | "VERIFICATION_ITEM_NOT_FOUND"
): never => {
    if (code === "42501") {
        throw new AdminVerificationServiceError("FORBIDDEN");
    }
    if (code === "P0002" && notFoundCode) {
        throw new AdminVerificationServiceError(notFoundCode);
    }
    if (code === "55000") {
        throw new AdminVerificationServiceError("VERIFICATION_INVALID_STATE");
    }
    throw new AdminVerificationServiceError("ADMIN_VERIFICATION_UNAVAILABLE");
};

export const listAdminVerificationQueue = async (
    actorUserId: string,
    query: AdminVerificationQueueQuery
) => {
    const { data, error } = await getAdminClient().rpc(
        "list_admin_verification_queue",
        {
            p_actor_user_id: actorUserId,
            p_status: query.status ?? null,
            p_item_type: query.itemType ?? null,
            p_organization_id: query.organizationId ?? null,
            p_limit: query.limit ?? 50
        }
    );

    if (error) {
        return mapRpcError(error.code);
    }

    const parsed = z.array(queueRowSchema).safeParse(data);
    if (!parsed.success) {
        throw new AdminVerificationServiceError("INTERNAL_SERVER_ERROR");
    }

    return parsed.data.map((row) => ({
        verificationCaseId: row.verification_case_id,
        verificationItemId: row.verification_item_id,
        organizationId: row.organization_id,
        organizationName: row.organization_name,
        businessId: row.business_id,
        businessLegalName: row.business_legal_name,
        itemType: row.item_type,
        status: row.item_status,
        verificationMethod: row.verification_method,
        caseCreatedAt: row.case_created_at,
        caseSubmittedAt: row.case_submitted_at,
        itemCreatedAt: row.item_created_at,
        itemUpdatedAt: row.item_updated_at,
        reviewedAt: row.item_reviewed_at
    }));
};

export const getAdminVerificationCase = async (
    actorUserId: string,
    verificationCaseId: string
) => {
    const { data, error } = await getAdminClient().rpc(
        "get_admin_verification_case",
        {
            p_actor_user_id: actorUserId,
            p_verification_case_id: verificationCaseId
        }
    );

    if (error) {
        return mapRpcError(error.code, "VERIFICATION_CASE_NOT_FOUND");
    }

    const parsed = caseDetailSchema.safeParse(data);
    if (!parsed.success) {
        throw new AdminVerificationServiceError("INTERNAL_SERVER_ERROR");
    }

    return {
        id: parsed.data.verification_case_id,
        status: parsed.data.status,
        submittedAt: parsed.data.submitted_at,
        startedReviewAt: parsed.data.started_review_at,
        completedAt: parsed.data.completed_at,
        createdAt: parsed.data.created_at,
        updatedAt: parsed.data.updated_at,
        organization: {
            id: parsed.data.organization.id,
            name: parsed.data.organization.name,
            organizationType: parsed.data.organization.organization_type
        },
        business: {
            id: parsed.data.business.id,
            legalName: parsed.data.business.legal_name,
            dbaName: parsed.data.business.dba_name,
            einLastFour: parsed.data.business.ein_last_four,
            cannabisLicenseNumber:
                parsed.data.business.cannabis_license_number,
            cannabisLicenseState: parsed.data.business.cannabis_license_state
        },
        items: parsed.data.items.map((item) => ({
            id: item.id,
            itemType: item.item_type,
            status: item.status,
            verificationMethod: item.verification_method,
            reviewedByUserId: item.reviewed_by_user_id,
            reviewedAt: item.reviewed_at,
            rejectionReason: item.rejection_reason,
            correctionNotes: item.correction_notes,
            createdAt: item.created_at,
            updatedAt: item.updated_at,
            history: item.history.map((entry) => ({
                id: entry.id,
                previousStatus: entry.previous_status,
                newStatus: entry.new_status,
                action: entry.action,
                reason: entry.reason,
                notes: entry.notes,
                actorUserId: entry.actor_user_id,
                createdAt: entry.created_at
            })),
            documents: item.documents.map((document) => ({
                id: document.id,
                documentType: document.document_type,
                fileName: document.file_name,
                mimeType: document.mime_type,
                fileSizeBytes: document.file_size_bytes,
                uploadedByUserId: document.uploaded_by_user_id,
                uploadedAt: document.uploaded_at,
                reviewStatus: document.review_status,
                reviewedByUserId: document.reviewed_by_user_id,
                reviewedAt: document.reviewed_at,
                reviewNotes: document.review_notes
            })),
            einVerificationAttempts: item.ein_verification_attempts.map(
                (attempt) => ({
                    id: attempt.id,
                    provider: attempt.provider,
                    providerReference: attempt.provider_reference,
                    resultStatus: attempt.result_status,
                    resultReason: attempt.result_reason,
                    requestedAt: attempt.requested_at,
                    completedAt: attempt.completed_at
                })
            ),
            cannabisLicenseVerifications:
                item.cannabis_license_verifications.map((verification) => ({
                    id: verification.id,
                    stateCode: verification.state_code,
                    licenseNumber: verification.license_number,
                    registryName: verification.registry_name,
                    registryUrl: verification.registry_url,
                    lookedUpByUserId: verification.looked_up_by_user_id,
                    lookedUpAt: verification.looked_up_at,
                    resultStatus: verification.result_status,
                    resultNotes: verification.result_notes
                }))
        }))
    };
};

export const reviewAdminVerificationItem = async (
    actorUserId: string,
    verificationItemId: string,
    input: AdminVerificationReviewInput
) => {
    const { data, error } = await getAdminClient()
        .rpc("review_admin_verification_item", {
            p_actor_user_id: actorUserId,
            p_verification_item_id: verificationItemId,
            p_decision: input.decision,
            p_reason: input.reason || null
        })
        .single();

    if (error) {
        return mapRpcError(error.code, "VERIFICATION_ITEM_NOT_FOUND");
    }

    const parsed = reviewResultSchema.safeParse(data);
    if (!parsed.success) {
        throw new AdminVerificationServiceError("INTERNAL_SERVER_ERROR");
    }

    return {
        id: parsed.data.verification_item_id,
        verificationCaseId: parsed.data.verification_case_id,
        organizationId: parsed.data.organization_id,
        previousStatus: parsed.data.previous_status,
        status: parsed.data.new_status,
        reviewedByUserId: parsed.data.reviewed_by_user_id,
        reviewedAt: parsed.data.reviewed_at
    };
};
