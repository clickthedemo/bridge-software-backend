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

const envSchema = z.object({
    NODE_ENV: z
        .enum(["development", "test", "production"])
        .default("development"),

    API_PORT: z.coerce.number().int().positive().default(4000),

    API_URL: z.url().default("http://localhost:4000"),

    WEB_URL: z.url().default("http://localhost:5173"),

    SUPABASE_URL: z.url(),

    SUPABASE_ANON_KEY: z.string().min(1),

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
