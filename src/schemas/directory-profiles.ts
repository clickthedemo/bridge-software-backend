import { z } from "zod";

const slugSchema = z
    .string()
    .trim()
    .min(3)
    .max(100)
    .regex(
        /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
        "Slug must contain lowercase letters, numbers, and single hyphens only."
    );

const websiteUrlSchema = z
    .string()
    .trim()
    .max(2048)
    .url()
    .refine((value) => {
        const protocol = new URL(value).protocol;
        return protocol === "http:" || protocol === "https:";
    }, "Website URL must use HTTP or HTTPS.");

export const directoryProfileOrganizationParamsSchema = z.object({
    organizationId: z.uuid()
});

export const publicDirectoryProfileParamsSchema = z.object({
    slug: slugSchema
});

export const publicDirectoryProfilesQuerySchema = z
    .object({
        q: z.string().trim().max(100).optional(),
        organizationType: z
            .enum(["brand", "retailer", "dispensary"])
            .optional(),
        sort: z.enum(["name_asc", "name_desc"]).default("name_asc"),
        limit: z.coerce.number().int().min(1).max(50).default(20),
        cursor: z.string().trim().min(1).max(1000).optional()
    })
    .strict();

export const directoryProfileAdminParamsSchema = z.object({
    profileId: z.uuid()
});

export const directoryProfileReviewReasonSchema = z
    .object({
        reason: z.string().trim().min(1).max(2000)
    })
    .strict();

export const directoryProfileLogoUploadSchema = z
    .object({
        contentType: z.enum(["image/png", "image/jpeg", "image/webp"]),
        fileSize: z.number().int().min(1).max(2 * 1024 * 1024)
    })
    .strict();

export const putDirectoryProfileSchema = z
    .object({
        businessId: z.uuid(),
        slug: slugSchema,
        displayName: z.string().trim().min(1).max(200),
        summary: z.string().trim().max(1000).nullable().optional(),
        websiteUrl: websiteUrlSchema.nullable().optional()
    })
    .strict();

export type PutDirectoryProfileInput = z.infer<
    typeof putDirectoryProfileSchema
>;
export type DirectoryProfileReviewReasonInput = z.infer<
    typeof directoryProfileReviewReasonSchema
>;
export type PublicDirectoryProfilesQuery = z.infer<
    typeof publicDirectoryProfilesQuerySchema
>;
export type DirectoryProfileLogoUploadInput = z.infer<
    typeof directoryProfileLogoUploadSchema
>;
