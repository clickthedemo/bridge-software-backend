import { z } from "zod";

const optionalQueryValue = <T extends z.ZodType>(schema: T) =>
    z.preprocess(
        (value) => (value === "" ? undefined : value),
        schema.optional()
    );

export const adminUsersQuerySchema = z
    .object({
        page: optionalQueryValue(z.coerce.number().int().min(1)).default(1),
        pageSize: optionalQueryValue(
            z.coerce.number().int().min(1).max(100)
        ).default(50)
    })
    .strict();

export type AdminUsersQuery = z.infer<typeof adminUsersQuerySchema>;
