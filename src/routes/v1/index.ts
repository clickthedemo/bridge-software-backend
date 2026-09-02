import { Router } from "express";

import { adminVerificationRouter } from "./admin-verification.js";
import { authRouter } from "./auth.js";
import { einRouter } from "./ein.js";
import { organizationsRouter } from "./organizations.js";
import { sessionRouter } from "./session.js";
import { systemRouter } from "./system.js";

const router = Router();

router.get("/", (_req, res) => {
    res.status(200).json({
        api: "thebridge",
        version: "v1",
        status: "ok"
    });
});

router.use(systemRouter);
router.use("/auth", authRouter);
router.use("/session", sessionRouter);
router.use("/admin", adminVerificationRouter);
router.use("/organizations", organizationsRouter);
router.use(einRouter);

export { router as v1Router };
