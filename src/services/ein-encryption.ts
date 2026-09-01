import {
    createCipheriv,
    createDecipheriv,
    randomBytes
} from "node:crypto";

import { env } from "../config/index.js";

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;

export type EncryptedEin = {
    ciphertext: string;
    iv: string;
    authTag: string;
    keyVersion: number;
};

export class EinEncryptionUnavailableError extends Error {
    constructor() {
        super("EIN encryption is unavailable.");
        this.name = "EinEncryptionUnavailableError";
    }
}

export class EinDecryptionError extends Error {
    constructor() {
        super("EIN decryption failed.");
        this.name = "EinDecryptionError";
    }
}

// This resolver intentionally models keys by version. A future implementation
// can resolve older versions from a key map or KMS without changing storage.
const resolveKey = (keyVersion: number): Buffer => {
    if (
        !env.EIN_ENCRYPTION_KEY ||
        keyVersion !== env.EIN_ENCRYPTION_KEY_VERSION
    ) {
        throw new EinEncryptionUnavailableError();
    }

    const key = Buffer.from(env.EIN_ENCRYPTION_KEY, "base64");

    if (key.byteLength !== 32) {
        throw new EinEncryptionUnavailableError();
    }

    return key;
};

export const encryptEin = (ein: string): EncryptedEin => {
    const keyVersion = env.EIN_ENCRYPTION_KEY_VERSION;
    const key = resolveKey(keyVersion);
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGORITHM, key, iv, {
        authTagLength: AUTH_TAG_BYTES
    });
    const ciphertext = Buffer.concat([
        cipher.update(ein, "utf8"),
        cipher.final()
    ]);

    return {
        ciphertext: ciphertext.toString("base64"),
        iv: iv.toString("base64"),
        authTag: cipher.getAuthTag().toString("base64"),
        keyVersion
    };
};

export const decryptEin = (encrypted: EncryptedEin): string => {
    try {
        const key = resolveKey(encrypted.keyVersion);
        const iv = Buffer.from(encrypted.iv, "base64");
        const authTag = Buffer.from(encrypted.authTag, "base64");
        const ciphertext = Buffer.from(encrypted.ciphertext, "base64");

        if (iv.byteLength !== IV_BYTES || authTag.byteLength !== AUTH_TAG_BYTES) {
            throw new EinDecryptionError();
        }

        const decipher = createDecipheriv(ALGORITHM, key, iv, {
            authTagLength: AUTH_TAG_BYTES
        });
        decipher.setAuthTag(authTag);

        return Buffer.concat([
            decipher.update(ciphertext),
            decipher.final()
        ]).toString("utf8");
    } catch (error) {
        if (error instanceof EinEncryptionUnavailableError) {
            throw error;
        }

        throw new EinDecryptionError();
    }
};
