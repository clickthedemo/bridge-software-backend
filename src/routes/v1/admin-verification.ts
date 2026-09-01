import { Router, type Response } from "express";

import { loadApplicationIdentity } from "../../middleware/application-identity.js";
import { requireAuthentication } from "../../middleware/authentication.js";
import { requirePermission } from "../../middleware/authorization.js";
import {
    validateBody,
    validateParams,
    validateQuery
} from "../../middleware/validation.js";
import {
    adminVerificationCaseParamsSchema,
    adminVerificationItemParamsSchema,
    adminVerificationQueueQuerySchema,
    adminVerificationReviewSchema,
    type AdminVerificationQueueQuery,
    type AdminVerificationReviewInput
} from "../../schemas/admin-verification.js";
import {
    AdminVerificationServiceError,
    getAdminVerificationCase,
    listAdminVerificationQueue,
    reviewAdminVerificationItem
} from "../../services/admin-verification.js";

const router = Router();

const sendAdminVerificationError = (
    res: Response,
    error: unknown
): void => {
    if (!(error instanceof AdminVerificationServiceError)) {
        res.status(500).json({
            error: "INTERNAL_SERVER_ERROR",
            message: "An unexpected error occurred."
        });
        return;
    }

    const statusByCode: Record<AdminVerificationServiceError["code"], number> = {
        FORBIDDEN: 403,
        VERIFICATION_CASE_NOT_FOUND: 404,
        VERIFICATION_ITEM_NOT_FOUND: 404,
        VERIFICATION_INVALID_STATE: 409,
        ADMIN_VERIFICATION_UNAVAILABLE: 503,
        INTERNAL_SERVER_ERROR: 500
    };
    const messageByCode: Record<AdminVerificationServiceError["code"], string> = {
        FORBIDDEN: "You do not have permission to perform this action.",
        VERIFICATION_CASE_NOT_FOUND: "Verification case not found.",
        VERIFICATION_ITEM_NOT_FOUND: "Verification item not found.",
        VERIFICATION_INVALID_STATE:
            "The verification item cannot be reviewed from its current state.",
        ADMIN_VERIFICATION_UNAVAILABLE:
            "Admin verification is temporarily unavailable.",
        INTERNAL_SERVER_ERROR: "An unexpected error occurred."
    };

    res.status(statusByCode[error.code]).json({
        error: error.code,
        message: messageByCode[error.code]
    });
};

router.get(
    "/verification-queue",
    requireAuthentication,
    loadApplicationIdentity,
    requirePermission("admin:verification_queue"),
    validateQuery(adminVerificationQueueQuerySchema, "adminVerificationQuery"),
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
            const entries = await listAdminVerificationQueue(
                authentication.user.id,
                res.locals.adminVerificationQuery as AdminVerificationQueueQuery
            );
            res.status(200).json({ entries });
        } catch (error) {
            sendAdminVerificationError(res, error);
        }
    }
);

router.get(
    "/verification-cases/:verificationCaseId",
    requireAuthentication,
    loadApplicationIdentity,
    requirePermission("admin:verification_queue"),
    validateParams(adminVerificationCaseParamsSchema),
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
            const { verificationCaseId } = req.params as {
                verificationCaseId: string;
            };
            const verificationCase = await getAdminVerificationCase(
                authentication.user.id,
                verificationCaseId
            );
            res.status(200).json({ verificationCase });
        } catch (error) {
            sendAdminVerificationError(res, error);
        }
    }
);

router.post(
    "/verification-items/:verificationItemId/review",
    requireAuthentication,
    loadApplicationIdentity,
    requirePermission("admin:verification_review"),
    validateParams(adminVerificationItemParamsSchema),
    validateBody(adminVerificationReviewSchema),
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
            const { verificationItemId } = req.params as {
                verificationItemId: string;
            };
            const verificationItem = await reviewAdminVerificationItem(
                authentication.user.id,
                verificationItemId,
                req.body as AdminVerificationReviewInput
            );
            res.status(200).json({ verificationItem });
        } catch (error) {
            sendAdminVerificationError(res, error);
        }
    }
);

export { router as adminVerificationRouter };
