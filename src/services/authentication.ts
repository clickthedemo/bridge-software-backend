import { env } from "../config/index.js";
import { createPublicSupabaseClient } from "../lib/supabase.js";
import type {
    EmailRequestInput,
    LoginInput,
    RegistrationInput,
    ResetPasswordInput
} from "../schemas/authentication.js";

export type AuthenticationFailureCode =
    | "AUTH_REGISTRATION_FAILED"
    | "AUTH_LOGIN_FAILED"
    | "AUTH_PASSWORD_RESET_FAILED"
    | "AUTH_PROVIDER_UNAVAILABLE";

export class AuthenticationServiceError extends Error {
    constructor(public readonly code: AuthenticationFailureCode) {
        super(code);
        this.name = "AuthenticationServiceError";
    }
}

const providerFailure = (): never => {
    throw new AuthenticationServiceError("AUTH_PROVIDER_UNAVAILABLE");
};

const throwIfProviderUnavailable = (status?: number): void => {
    if (status === 0 || (status !== undefined && status >= 500)) {
        providerFailure();
    }
};

export const register = async (input: RegistrationInput) => {
    const client = createPublicSupabaseClient();

    try {
        const { data, error } = await client.auth.signUp({
            email: input.email,
            password: input.password
        });

        if (error) {
            throwIfProviderUnavailable(error.status);
            throw new AuthenticationServiceError("AUTH_REGISTRATION_FAILED");
        }

        if (!data.user) {
            throw new AuthenticationServiceError("AUTH_REGISTRATION_FAILED");
        }

        return {
            user: {
                id: data.user.id,
                email: data.user.email ?? input.email
            },
            emailConfirmationRequired: data.session === null
        };
    } catch (error) {
        if (error instanceof AuthenticationServiceError) {
            throw error;
        }
        return providerFailure();
    }
};

export const login = async (input: LoginInput) => {
    const client = createPublicSupabaseClient();

    try {
        const { data, error } = await client.auth.signInWithPassword(input);

        if (error) {
            throwIfProviderUnavailable(error.status);
            throw new AuthenticationServiceError("AUTH_LOGIN_FAILED");
        }

        if (!data.user || !data.session) {
            throw new AuthenticationServiceError("AUTH_LOGIN_FAILED");
        }

        return {
            accessToken: data.session.access_token,
            refreshToken: data.session.refresh_token,
            expiresAt: data.session.expires_at ?? null,
            expiresIn: data.session.expires_in,
            tokenType: data.session.token_type,
            user: {
                id: data.user.id,
                email: data.user.email ?? null
            }
        };
    } catch (error) {
        if (error instanceof AuthenticationServiceError) {
            throw error;
        }
        return providerFailure();
    }
};

export const resendVerification = async (
    input: EmailRequestInput
): Promise<void> => {
    const client = createPublicSupabaseClient();

    try {
        const { error } = await client.auth.resend({
            type: "signup",
            email: input.email
        });
        throwIfProviderUnavailable(error?.status);
    } catch {
        providerFailure();
    }
};

export const requestPasswordReset = async (
    input: EmailRequestInput
): Promise<void> => {
    const client = createPublicSupabaseClient();

    try {
        const { error } = await client.auth.resetPasswordForEmail(input.email, {
            redirectTo: env.PASSWORD_RESET_REDIRECT_URL
        });
        throwIfProviderUnavailable(error?.status);
    } catch {
        providerFailure();
    }
};

export const resetPassword = async (
    userId: string,
    accessToken: string,
    input: ResetPasswordInput
): Promise<void> => {
    const client = createPublicSupabaseClient();

    try {
        // Supabase recovery links establish a session in the redirecting client.
        // The frontend passes that session's access token as the Bearer token and
        // its paired refresh token here; no custom reset token is accepted.
        const { data: sessionData, error: sessionError } =
            await client.auth.setSession({
                access_token: accessToken,
                refresh_token: input.refreshToken
            });

        if (
            sessionError ||
            !sessionData.session ||
            sessionData.session.user.id !== userId
        ) {
            throw new AuthenticationServiceError(
                "AUTH_PASSWORD_RESET_FAILED"
            );
        }

        const { error } = await client.auth.updateUser({
            password: input.newPassword
        });

        if (error) {
            throw new AuthenticationServiceError(
                "AUTH_PASSWORD_RESET_FAILED"
            );
        }
    } catch (error) {
        if (error instanceof AuthenticationServiceError) {
            throw error;
        }
        providerFailure();
    }
};
