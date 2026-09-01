import { createClient, type SupabaseClient } from "@supabase/supabase-js";

import { env } from "../config/index.js";

const serverAuthOptions = {
    autoRefreshToken: false,
    detectSessionInUrl: false,
    persistSession: false
} as const;

export const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
    auth: serverAuthOptions
});

export const createPublicSupabaseClient = (): SupabaseClient => {
    return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
        auth: serverAuthOptions
    });
};

export class SupabaseAdminNotConfiguredError extends Error {
    constructor() {
        super("Supabase admin client is not configured.");
        this.name = "SupabaseAdminNotConfiguredError";
    }
}

export const createAdminSupabaseClient = (): SupabaseClient => {
    if (!env.SUPABASE_SERVICE_ROLE_KEY) {
        throw new SupabaseAdminNotConfiguredError();
    }

    return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
        auth: serverAuthOptions
    });
};

export const createUserScopedSupabaseClient = (
    accessToken: string
): SupabaseClient => {
    return createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
        auth: serverAuthOptions,
        global: {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        }
    });
};
