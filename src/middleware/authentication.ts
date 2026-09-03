import type { User } from "@supabase/supabase-js";
import type { RequestHandler } from "express";

import { supabase } from "../lib/supabase.js";
import { createPublicSupabaseClient } from "../lib/supabase.js";
import { getCookieAuthTokens, setAuthCookies } from "../http/auth-cookies.js";

declare global {
    namespace Express {
        interface Request {
            authentication?: {
                user: User;
                accessToken: string;
                refreshToken?: string;
                transport: "bearer" | "cookie";
            };
        }
    }
}

const unauthorized = {
    error: "UNAUTHORIZED",
    message: "A valid authentication credential is required."
} as const;

export const requireAuthentication: RequestHandler = async (req, res, next) => {
    const authorization = req.get("authorization");
    const match = authorization?.match(/^Bearer\s+(\S+)$/i);
    const bearerToken = match?.[1];
    const cookieTokens = getCookieAuthTokens(req);
    let accessToken = bearerToken ?? cookieTokens.accessToken;
    let refreshToken = cookieTokens.refreshToken;

    if (!accessToken) {
        res.status(401).json(unauthorized);
        return;
    }

    try {
        let { data, error } = await supabase.auth.getUser(accessToken);

        if ((error || !data.user) && !bearerToken && cookieTokens.refreshToken) {
            const client = createPublicSupabaseClient();
            const refreshed = await client.auth.refreshSession({
                refresh_token: cookieTokens.refreshToken
            });
            if (!refreshed.error && refreshed.data.session && refreshed.data.user) {
                accessToken = refreshed.data.session.access_token;
                refreshToken = refreshed.data.session.refresh_token;
                data = { user: refreshed.data.user };
                error = null;
                setAuthCookies(res, {
                    accessToken,
                    refreshToken: refreshed.data.session.refresh_token,
                    expiresIn: refreshed.data.session.expires_in
                });
            }
        }

        if (error || !data.user) {
            res.status(401).json(unauthorized);
            return;
        }

        req.authentication = {
            user: data.user,
            accessToken,
            ...(bearerToken ? {} : { refreshToken }),
            transport: bearerToken ? "bearer" : "cookie"
        };
        next();
    } catch {
        res.status(401).json(unauthorized);
    }
};
