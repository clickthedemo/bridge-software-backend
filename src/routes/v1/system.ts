import { createRequire } from "node:module";
import { Router } from "express";
import { z } from "zod";

import { env } from "../../config/index.js";

const require = createRequire(import.meta.url);
const packageMetadata = z
    .object({ version: z.string().min(1) })
    .parse(require("../../../package.json"));

const router = Router();

router.get("/health", (_req, res) => {
    res.status(200).json({
        status: "ok",
        service: "bridge-api"
    });
});

router.get("/version", (_req, res) => {
    res.status(200).json({
        service: "bridge-api",
        version: packageMetadata.version,
        environment: env.DEPLOYMENT_ENVIRONMENT ?? env.NODE_ENV
    });
});

export { router as systemRouter };
