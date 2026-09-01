import { z } from "zod";

export const organizationTypeSchema = z.enum([
    "brand",
    "retailer",
    "dispensary"
]);

export const createOrganizationSchema = z
    .object({
        name: z.string().trim().min(1).max(200),
        organizationType: organizationTypeSchema
    })
    .strict();

export const updateOrganizationSchema = z
    .object({
        name: z.string().trim().min(1).max(200).optional(),
        organizationType: organizationTypeSchema.optional()
    })
    .strict()
    .refine((value) => Object.keys(value).length > 0, {
        message: "At least one editable field is required."
    });

export const organizationParamsSchema = z.object({
    organizationId: z.uuid()
});

export type CreateOrganizationInput = z.infer<
    typeof createOrganizationSchema
>;
export type UpdateOrganizationInput = z.infer<
    typeof updateOrganizationSchema
>;
