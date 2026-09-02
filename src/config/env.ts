import { z } from "zod";

const optionalString = z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().min(1).optional()
);

const optionalEinEncryptionKey = z.preprocess(
    (value) => (value === "" ? undefined : value),
    z.string().refine((value) => {
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
            return false;
        }

        return Buffer.from(value, "base64").byteLength === 32;
    }, "EIN_ENCRYPTION_KEY must be a base64 encoded 32-byte key.").optional()
);

const corsOriginsSchema = z.string().transform((value, context) => {
    const origins = value
        .split(",")
        .map((origin) => origin.trim())
        .filter(Boolean);

    if (origins.length === 0 || origins.some((origin) => !z.url().safeParse(origin).success)) {
        context.addIssue({
            code: "custom",
            message: "CORS_ORIGINS must contain one or more comma-separated URLs."
        });
        return z.NEVER;
    }

    return origins;
});

const envSchema = z.object({
    NODE_ENV: z
        .enum(["development", "test", "production"])
        .default("development"),

    API_PORT: z.coerce.number().int().positive().default(4000),

    PORT: z.coerce.number().int().positive().optional(),

    API_URL: z.url().default("http://localhost:4000"),

    WEB_URL: z.url().default("http://localhost:5173"),

    CORS_ORIGINS: corsOriginsSchema,

    DEPLOYMENT_ENVIRONMENT: z
        .enum(["development", "test", "staging", "production"])
        .optional(),

    SUPABASE_URL: z.url(),

    SUPABASE_ANON_KEY: z.string().min(1),

    EMAIL_VERIFICATION_REDIRECT_URL: z.url(),

    PASSWORD_RESET_REDIRECT_URL: z.url(),

    SUPABASE_SERVICE_ROLE_KEY: optionalString,

    DATABASE_URL: optionalString,

    EIN_VERIFICATION_PROVIDER: optionalString,

    EIN_VERIFICATION_API_KEY: optionalString,

    EIN_ENCRYPTION_KEY: optionalEinEncryptionKey,

    EIN_ENCRYPTION_KEY_VERSION: z.coerce.number().int().positive().default(1)
});

const result = envSchema.safeParse(process.env);

if (!result.success) {
    console.error("Invalid environment configuration:");
    console.error(z.prettifyError(result.error));
    process.exit(1);
}

export const env = result.data;
