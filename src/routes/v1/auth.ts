import { Router, type Response } from "express";

import { requireAuthentication } from "../../middleware/authentication.js";
import { loadApplicationIdentity } from "../../middleware/application-identity.js";
import { validateBody } from "../../middleware/validation.js";
import {
    emailRequestSchema,
    loginSchema,
    registrationSchema,
    resetPasswordSchema,
    type EmailRequestInput,
    type LoginInput,
    type RegistrationInput,
    type ResetPasswordInput
} from "../../schemas/authentication.js";
import {
    AuthenticationServiceError,
    login,
    register,
    requestPasswordReset,
    resendVerification,
    resetPassword
} from "../../services/authentication.js";

const router = Router();

export const authFailureStatus = (error: AuthenticationServiceError): number => {
    switch (error.code) {
        case "INVALID_CREDENTIALS":
            return 401;
        case "EMAIL_NOT_VERIFIED":
            return 403;
        case "AUTH_RATE_LIMITED":
            return 429;
        case "AUTH_PROVIDER_UNAVAILABLE":
            return 503;
        default:
            return 400;
    }
};

const sendAuthFailure = (
    res: Response,
    error: unknown
): void => {
    if (error instanceof AuthenticationServiceError) {
        const messages: Partial<Record<typeof error.code, string>> = {
            AUTH_RATE_LIMITED:
                "Too many authentication requests. Please try again later.",
            EMAIL_NOT_VERIFIED: "Please verify your email before signing in.",
            INVALID_CREDENTIALS: "Invalid email or password.",
            AUTH_PROVIDER_UNAVAILABLE:
                "Authentication service is temporarily unavailable."
        };
        res.status(authFailureStatus(error)).json({
            error: error.code,
            message:
                messages[error.code] ??
                "The authentication request could not be completed."
        });
        return;
    }

    res.status(500).json({
        error: "INTERNAL_SERVER_ERROR",
        message: "An unexpected error occurred."
    });
};

router.post("/register", validateBody(registrationSchema), async (req, res) => {
    try {
        const result = await register(req.body as RegistrationInput);
        res.status(201).json(result);
    } catch (error) {
        sendAuthFailure(res, error);
    }
});

router.post("/login", validateBody(loginSchema), async (req, res) => {
    try {
        const result = await login(req.body as LoginInput);
        res.status(200).json(result);
    } catch (error) {
        sendAuthFailure(res, error);
    }
});

router.post(
    "/resend-verification",
    validateBody(emailRequestSchema),
    async (req, res) => {
        try {
            await resendVerification(req.body as EmailRequestInput);
            res.status(202).json({
                code: "AUTH_EMAIL_REQUEST_ACCEPTED",
                message:
                    "If the account is eligible, a verification email will be sent."
            });
        } catch (error) {
            sendAuthFailure(res, error);
        }
    }
);

router.post(
    "/forgot-password",
    validateBody(emailRequestSchema),
    async (req, res) => {
        try {
            await requestPasswordReset(req.body as EmailRequestInput);
            res.status(202).json({
                code: "AUTH_EMAIL_REQUEST_ACCEPTED",
                message:
                    "If the account is eligible, a password recovery email will be sent."
            });
        } catch (error) {
            sendAuthFailure(res, error);
        }
    }
);

router.post(
    "/reset-password",
    requireAuthentication,
    validateBody(resetPasswordSchema),
    async (req, res) => {
        const authentication = req.authentication;

        if (!authentication) {
            res.status(401).json({
                error: "UNAUTHORIZED",
                message: "A valid Bearer access token is required."
            });
            return;
        }

        try {
            await resetPassword(
                authentication.user.id,
                authentication.accessToken,
                req.body as ResetPasswordInput
            );
            res.status(200).json({
                code: "AUTH_PASSWORD_RESET_COMPLETED",
                message: "Password updated successfully."
            });
        } catch (error) {
            sendAuthFailure(res, error);
        }
    }
);

router.get("/me", requireAuthentication, loadApplicationIdentity, (req, res) => {
    const identity = req.identity;

    if (!identity) {
        res.status(503).json({
            error: "APPLICATION_IDENTITY_UNAVAILABLE",
            message: "Application identity is temporarily unavailable."
        });
        return;
    }

    res.status(200).json({
        user: {
            id: identity.userId,
            email: identity.email,
            accountType: identity.accountType,
            platformRoles: identity.platformRoles,
            profile: identity.profile
        },
        memberships: identity.memberships
    });
});

export { router as authRouter };
