import type { RequestHandler } from "express";

import { resolveApplicationIdentity } from "../services/application-identity.js";
import type { ApplicationIdentity } from "../types/application-identity.js";

declare global {
    namespace Express {
        interface Request {
            identity?: ApplicationIdentity;
        }
    }
}

export const loadApplicationIdentity: RequestHandler = async (
    req,
    res,
    next
) => {
    const authentication = req.authentication;

    if (!authentication) {
        res.status(401).json({
            error: "UNAUTHORIZED",
            message: "A valid Bearer access token is required."
        });
        return;
    }

    try {
        req.identity = await resolveApplicationIdentity(
            authentication.user,
            authentication.accessToken
        );
        next();
    } catch {
        res.status(503).json({
            error: "APPLICATION_IDENTITY_UNAVAILABLE",
            message: "Application identity is temporarily unavailable."
        });
    }
};
