import cors from "cors";
import express from "express";
import helmet from "helmet";

import { env } from "./config/index.js";
import { v1Router } from "./routes/v1/index.js";

const app = express();

app.disable("x-powered-by");

app.use(helmet());

app.use(
    cors({
        origin: env.WEB_URL,
        credentials: true
    })
);

app.use(express.json({ limit: "1mb" }));

app.get("/", (_req, res) => {
    res.status(200).send("BRIDGE API running");
});

app.get("/health", (_req, res) => {
    res.status(200).json({
        status: "ok",
        service: "thebridge-api"
    });
});

app.use("/api/v1", v1Router);

export { app };
