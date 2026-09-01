import { Router, type Response } from "express";

import { loadApplicationIdentity } from "../../middleware/application-identity.js";
import { requireAuthentication } from "../../middleware/authentication.js";
import { requirePermission } from "../../middleware/authorization.js";
import {
    validateBody,
    validateParams
} from "../../middleware/validation.js";
import {
    createOrganizationSchema,
    organizationParamsSchema,
    updateOrganizationSchema,
    type CreateOrganizationInput,
    type UpdateOrganizationInput
} from "../../schemas/organizations.js";
import {
    createOrganization,
    getOrganization,
    listOrganizations,
    OrganizationServiceError,
    updateOrganization
} from "../../services/organizations.js";

const router = Router();
const organizationIdFromParams = (req: { params: { organizationId?: string } }) =>
    req.params.organizationId;

const sendOrganizationError = (res: Response, error: unknown): void => {
    if (error instanceof OrganizationServiceError) {
        const status = error.code === "ORGANIZATION_NOT_FOUND" ? 404 : 500;
        res.status(status).json({
            error: error.code,
            message:
                error.code === "ORGANIZATION_NOT_FOUND"
                    ? "Organization not found."
                    : "The organization request could not be completed."
        });
        return;
    }

    res.status(500).json({
        error: "INTERNAL_SERVER_ERROR",
        message: "An unexpected error occurred."
    });
};

router.post(
    "/",
    requireAuthentication,
    validateBody(createOrganizationSchema),
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
            const organization = await createOrganization(
                authentication.accessToken,
                req.body as CreateOrganizationInput
            );
            res.status(201).json({ organization });
        } catch (error) {
            sendOrganizationError(res, error);
        }
    }
);

router.get(
    "/",
    requireAuthentication,
    loadApplicationIdentity,
    (req, res) => {
        const identity = req.identity;

        if (!identity) {
            res.status(500).json({
                error: "INTERNAL_SERVER_ERROR",
                message: "An unexpected error occurred."
            });
            return;
        }

        res.status(200).json({
            organizations: listOrganizations(identity)
        });
    }
);

router.get(
    "/:organizationId",
    requireAuthentication,
    loadApplicationIdentity,
    validateParams(organizationParamsSchema),
    requirePermission("organization:read", organizationIdFromParams),
    async (req, res) => {
        const authentication = req.authentication;
        const membership = req.identity?.memberships.find(
            ({ organizationId }) =>
                organizationId === req.params.organizationId
        );

        if (!authentication || !membership) {
            res.status(404).json({
                error: "ORGANIZATION_NOT_FOUND",
                message: "Organization not found."
            });
            return;
        }

        try {
            const organization = await getOrganization(
                authentication.accessToken,
                membership
            );
            res.status(200).json({ organization });
        } catch (error) {
            sendOrganizationError(res, error);
        }
    }
);

router.patch(
    "/:organizationId",
    requireAuthentication,
    loadApplicationIdentity,
    validateParams(organizationParamsSchema),
    requirePermission("organization:update", organizationIdFromParams),
    validateBody(updateOrganizationSchema),
    async (req, res) => {
        const authentication = req.authentication;
        const membership = req.identity?.memberships.find(
            ({ organizationId }) =>
                organizationId === req.params.organizationId
        );

        if (!authentication || !membership) {
            res.status(404).json({
                error: "ORGANIZATION_NOT_FOUND",
                message: "Organization not found."
            });
            return;
        }

        try {
            const organization = await updateOrganization(
                authentication.accessToken,
                membership,
                req.body as UpdateOrganizationInput
            );
            res.status(200).json({ organization });
        } catch (error) {
            sendOrganizationError(res, error);
        }
    }
);

export { router as organizationsRouter };
