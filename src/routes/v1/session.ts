import { Router, type RequestHandler } from "express";

import { loadApplicationIdentity } from "../../middleware/application-identity.js";
import { requireAuthentication } from "../../middleware/authentication.js";
import { buildSessionClaims } from "../../services/session.js";

const router = Router();

export const sessionHandler: RequestHandler = (req, res) => {
    if (!req.identity) {
        res.status(503).json({
            error: "APPLICATION_IDENTITY_UNAVAILABLE",
            message: "Application identity is temporarily unavailable."
        });
        return;
    }

    res.status(200).json(buildSessionClaims(req.identity));
};

router.get(
    "/",
    requireAuthentication,
    loadApplicationIdentity,
    sessionHandler
);

export { router as sessionRouter };
