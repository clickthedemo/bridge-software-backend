import type { User } from "@supabase/supabase-js";
import type { RequestHandler } from "express";

import { supabase } from "../lib/supabase.js";

declare global {
    namespace Express {
        interface Request {
            authentication?: {
                user: User;
                accessToken: string;
            };
        }
    }
}

const unauthorized = {
    error: "UNAUTHORIZED",
    message: "A valid Bearer access token is required."
} as const;

export const requireAuthentication: RequestHandler = async (req, res, next) => {
    const authorization = req.get("authorization");
    const match = authorization?.match(/^Bearer\s+(\S+)$/i);
    const accessToken = match?.[1];

    if (!accessToken) {
        res.status(401).json(unauthorized);
        return;
    }

    try {
        const { data, error } = await supabase.auth.getUser(accessToken);

        if (error || !data.user) {
            res.status(401).json(unauthorized);
            return;
        }

        req.authentication = {
            user: data.user,
            accessToken
        };
        next();
    } catch {
        res.status(401).json(unauthorized);
    }
};
