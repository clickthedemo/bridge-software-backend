import type { RequestHandler } from "express";
import type { ZodType } from "zod";

export const validateBody = (schema: ZodType): RequestHandler => {
    return (req, res, next) => {
        const result = schema.safeParse(req.body);

        if (!result.success) {
            res.status(400).json({
                error: "VALIDATION_ERROR",
                message: "The request body is invalid.",
                details: result.error.issues.map((issue) => ({
                    path: issue.path.join("."),
                    message: issue.message
                }))
            });
            return;
        }

        req.body = result.data;
        next();
    };
};

export const validateParams = (schema: ZodType): RequestHandler => {
    return (req, res, next) => {
        const result = schema.safeParse(req.params);

        if (!result.success) {
            res.status(400).json({
                error: "VALIDATION_ERROR",
                message: "The request parameters are invalid.",
                details: result.error.issues.map((issue) => ({
                    path: issue.path.join("."),
                    message: issue.message
                }))
            });
            return;
        }

        req.params = result.data as typeof req.params;
        next();
    };
};

export const validateQuery = (
    schema: ZodType,
    localsKey = "validatedQuery"
): RequestHandler => {
    return (req, res, next) => {
        const result = schema.safeParse(req.query);

        if (!result.success) {
            res.status(400).json({
                error: "VALIDATION_ERROR",
                message: "The request query is invalid.",
                details: result.error.issues.map((issue) => ({
                    path: issue.path.join("."),
                    message: issue.message
                }))
            });
            return;
        }

        res.locals[localsKey] = result.data;
        next();
    };
};
