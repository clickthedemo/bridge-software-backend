import type { Request, Response } from "express";

import { env } from "../config/index.js";

export const ACCESS_TOKEN_COOKIE = "bridge_access_token";
export const REFRESH_TOKEN_COOKIE = "bridge_refresh_token";

export const getCookieSecurity = (nodeEnv: typeof env.NODE_ENV) => nodeEnv === "production"
    ? { secure: true, sameSite: "none" as const }
    : { secure: false, sameSite: "lax" as const };

const sharedCookieOptions = {
    httpOnly: true,
    path: "/api/v1",
    ...getCookieSecurity(env.NODE_ENV)
} as const;

export const readCookies = (req: Request): Record<string, string> => {
    const header = req.get("cookie");
    if (!header) return {};

    return Object.fromEntries(header.split(";").flatMap((part) => {
        const separator = part.indexOf("=");
        if (separator < 1) return [];
        const name = part.slice(0, separator).trim();
        const value = part.slice(separator + 1).trim();
        try {
            return [[name, decodeURIComponent(value)]];
        } catch {
            return [];
        }
    }));
};

export const setAuthCookies = (
    res: Response,
    session: {
        accessToken: string;
        refreshToken: string;
        expiresIn: number;
    }
): void => {
    res.cookie(ACCESS_TOKEN_COOKIE, session.accessToken, {
        ...sharedCookieOptions,
        maxAge: session.expiresIn * 1000
    });
    // Supabase refresh tokens have provider-controlled validity and rotation.
    // Keep this as a browser-session cookie instead of inventing a second TTL.
    res.cookie(REFRESH_TOKEN_COOKIE, session.refreshToken, sharedCookieOptions);
};

export const clearAuthCookies = (res: Response): void => {
    res.clearCookie(ACCESS_TOKEN_COOKIE, sharedCookieOptions);
    res.clearCookie(REFRESH_TOKEN_COOKIE, sharedCookieOptions);
};

export const getCookieAuthTokens = (req: Request) => {
    const cookies = readCookies(req);
    return {
        accessToken: cookies[ACCESS_TOKEN_COOKIE],
        refreshToken: cookies[REFRESH_TOKEN_COOKIE]
    };
};
