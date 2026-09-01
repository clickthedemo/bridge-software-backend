import { z } from "zod";

export const verificationCaseStatusSchema = z.enum([
    "draft",
    "submitted",
    "in_review",
    "action_required",
    "approved",
    "rejected",
    "cancelled"
]);

export const verificationItemTypeSchema = z.enum([
    "ein",
    "cannabis_license",
    "business_registration",
    "document"
]);

export const verificationItemStatusSchema = z.enum([
    "pending",
    "in_review",
    "verification_requested",
    "verified",
    "rejected",
    "correction_required",
    "not_applicable"
]);

const optionalQueryValue = <T extends z.ZodType>(schema: T) =>
    z.preprocess(
        (value) => (value === "" ? undefined : value),
        schema.optional()
    );

export const adminVerificationQueueQuerySchema = z
    .object({
        status: optionalQueryValue(verificationItemStatusSchema),
        itemType: optionalQueryValue(verificationItemTypeSchema),
        organizationId: optionalQueryValue(z.uuid()),
        limit: optionalQueryValue(z.coerce.number().int().min(1).max(100))
    })
    .strict();

export const adminVerificationCaseParamsSchema = z.object({
    verificationCaseId: z.uuid()
});

export const adminVerificationItemParamsSchema = z.object({
    verificationItemId: z.uuid()
});

export const adminVerificationReviewSchema = z
    .object({
        decision: z.enum(["verified", "rejected", "correction_required"]),
        reason: z.string().trim().max(2000).nullable().optional()
    })
    .strict()
    .superRefine((value, context) => {
        if (
            value.decision !== "verified" &&
            (!value.reason || value.reason.length === 0)
        ) {
            context.addIssue({
                code: "custom",
                path: ["reason"],
                message: "A reason is required for this review decision."
            });
        }
    });

export type AdminVerificationQueueQuery = z.infer<
    typeof adminVerificationQueueQuerySchema
>;
export type AdminVerificationReviewInput = z.infer<
    typeof adminVerificationReviewSchema
>;
