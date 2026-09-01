import { env } from "../config/index.js";

export interface EinVerificationProviderInput {
    ein: string;
    legalName: string;
}

export interface EinVerificationProviderResult {
    providerReference: string | null;
    status: "verified" | "rejected" | "correction_required";
    reason: string | null;
    rawResponse?: unknown;
}

export interface EinVerificationProvider {
    readonly name: string;
    verifyEin(
        input: EinVerificationProviderInput
    ): Promise<EinVerificationProviderResult>;
}

export class EinProviderNotConfiguredError extends Error {
    constructor() {
        super("EIN verification provider is not configured.");
        this.name = "EinProviderNotConfiguredError";
    }
}

export const getEinVerificationProvider = (): EinVerificationProvider => {
    if (!env.EIN_VERIFICATION_PROVIDER || !env.EIN_VERIFICATION_API_KEY) {
        throw new EinProviderNotConfiguredError();
    }

    // Provider adapters are registered here once a provider contract and
    // protected-response retention policy are approved. Configuration alone
    // must never create fake verified state.
    throw new EinProviderNotConfiguredError();
};
