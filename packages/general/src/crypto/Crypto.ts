/**
 * @license
 * Copyright 2022-2024 Matter.js Authors
 * SPDX-License-Identifier: Apache-2.0
 */

import * as mod from "@noble/curves/abstract/modular";
import * as utils from "@noble/curves/abstract/utils";
import { p256 } from "@noble/curves/p256";
import { MatterError, NoProviderError } from "../MatterError.js";
import { Endian } from "../util/Bytes.js";
import { DataReader } from "../util/DataReader.js";
import { PrivateKey } from "./Key.js";
import { Logger } from "../log/Logger.js";

const logger = Logger.get("Crypto");

export const ec = {
    p256,
    ...utils,
    ...mod,
};

export const CRYPTO_RANDOM_LENGTH = 32;
export const CRYPTO_ENCRYPT_ALGORITHM = "aes-128-ccm";
export const CRYPTO_HASH_ALGORITHM = "sha256";
export const CRYPTO_EC_CURVE = "prime256v1";
export const CRYPTO_EC_KEY_BYTES = 32;
export const CRYPTO_AUTH_TAG_LENGTH = 16;
export const CRYPTO_SYMMETRIC_KEY_LENGTH = 16;
export type CryptoDsaEncoding = "ieee-p1363" | "der";

export class CryptoVerifyError extends MatterError {}

export abstract class Crypto {
    static get: () => Crypto = () => {
        throw new NoProviderError("No provider configured");
    };

    abstract encrypt(key: Uint8Array, data: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array;

    static readonly encrypt = (key: Uint8Array, data: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array => {
        const result = Crypto.get().encrypt(key, data, nonce, aad);

        // Convert key, nonce, and aad to hex strings
        const keyString = utils.bytesToHex(key);
        const nonceString = utils.bytesToHex(nonce);
        const aadString = aad ? utils.bytesToHex(aad) : undefined;

        // Log the converted values
        logger.debug(`CRYPTOGRAPHIC_KEY_MATERIAL Key: ${keyString}, Nonce: ${nonceString}, AAD: ${aadString}`);

        return result;
    };

    abstract decrypt(key: Uint8Array, data: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array;

    static readonly decrypt = (key: Uint8Array, data: Uint8Array, nonce: Uint8Array, aad?: Uint8Array): Uint8Array => {
        const result = Crypto.get().decrypt(key, data, nonce, aad);

        // Convert key, nonce, and aad to hex strings
        const keyString = utils.bytesToHex(key);
        const nonceString = utils.bytesToHex(nonce);
        const aadString = aad ? utils.bytesToHex(aad) : undefined;

        // Log the converted values
        logger.debug(`CRYPTOGRAPHIC_KEY_MATERIAL Key: ${keyString}, Nonce: ${nonceString}, AAD: ${aadString}`);

        return result;
    };

    abstract getRandomData(length: number): Uint8Array;
    static readonly getRandomData = (length: number): Uint8Array => Crypto.get().getRandomData(length);

    static readonly getRandom = (): Uint8Array => Crypto.get().getRandomData(CRYPTO_RANDOM_LENGTH);

    static readonly getRandomUInt16 = (): number =>
        new DataReader(Crypto.get().getRandomData(2), Endian.Little).readUInt16();

    static readonly getRandomUInt32 = (): number =>
        new DataReader(Crypto.get().getRandomData(4), Endian.Little).readUInt32();

    static readonly getRandomBigUInt64 = (): bigint =>
        new DataReader(Crypto.get().getRandomData(8), Endian.Little).readUInt64();

    static readonly getRandomBigInt = (size: number, maxValue?: bigint): bigint => {
        const { bytesToNumberBE } = ec;
        if (maxValue === undefined) {
            return bytesToNumberBE(Crypto.getRandomData(size));
        }
        while (true) {
            const random = bytesToNumberBE(Crypto.getRandomData(size));
            if (random < maxValue) return random;
        }
    };

    abstract ecdhGeneratePublicKey(): { publicKey: Uint8Array; ecdh: any };
    static readonly ecdhGeneratePublicKey = (): { publicKey: Uint8Array; ecdh: any } => {
        const result = Crypto.get().ecdhGeneratePublicKey();

        // Convert publicKey to hex string
        const publicKeyString = utils.bytesToHex(result.publicKey);

        // Log the converted values
        logger.debug(`CRYPTOGRAPHIC_KEY_MATERIAL ECDH Generate PublicKey: ${publicKeyString}`);

        return result;
    };

    abstract ecdhGeneratePublicKeyAndSecret(peerPublicKey: Uint8Array): {
        publicKey: Uint8Array;
        sharedSecret: Uint8Array;
    };
    static readonly ecdhGeneratePublicKeyAndSecret = (
        peerPublicKey: Uint8Array,
    ): { publicKey: Uint8Array; sharedSecret: Uint8Array } =>
        Crypto.get().ecdhGeneratePublicKeyAndSecret(peerPublicKey);

    abstract ecdhGenerateSecret(peerPublicKey: Uint8Array, ecdh: any): Uint8Array;
    static readonly ecdhGenerateSecret = (peerPublicKey: Uint8Array, ecdh: any): Uint8Array => {
        const result = Crypto.get().ecdhGenerateSecret(peerPublicKey, ecdh);

        // Convert peerPublicKey to hex string
        const peerPublicKeyString = utils.bytesToHex(peerPublicKey);

        // Log the converted values
        logger.debug(`CRYPTOGRAPHIC_KEY_MATERIAL ECDH Generate Secret PeerPublicKey: ${peerPublicKeyString}, ECDH: ${ecdh}`);

        return result;
    };

    abstract hash(data: Uint8Array | Uint8Array[]): Uint8Array;
    static readonly hash = (data: Uint8Array | Uint8Array[]): Uint8Array => Crypto.get().hash(data);

    abstract pbkdf2(secret: Uint8Array, salt: Uint8Array, iteration: number, keyLength: number): Promise<Uint8Array>;
    static readonly pbkdf2 = (
        secret: Uint8Array,
        salt: Uint8Array,
        iteration: number,
        keyLength: number,
    ): Promise<Uint8Array> => {
        const result = Crypto.get().pbkdf2(secret, salt, iteration, keyLength);

        // Convert secret and salt to hex strings
        const secretString = utils.bytesToHex(secret);
        const saltString = utils.bytesToHex(salt);

        // Log the converted values
        logger.debug(`CRYPTOGRAPHIC_KEY_MATERIAL PBKDF2 Secret: ${secretString}, Salt: ${saltString}, Iteration: ${iteration}, KeyLength: ${keyLength}`);

        return result;
    };

    abstract hkdf(secret: Uint8Array, salt: Uint8Array, info: Uint8Array, length?: number): Promise<Uint8Array>;
    static readonly hkdf = (
        secret: Uint8Array,
        salt: Uint8Array,
        info: Uint8Array,
        length?: number,
    ): Promise<Uint8Array> => {
        const result = Crypto.get().hkdf(secret, salt, info, length);

        // Convert secret, salt, and info to hex strings
        const secretString = utils.bytesToHex(secret);
        const saltString = utils.bytesToHex(salt);
        const infoString = utils.bytesToHex(info);

        // Log the converted values
        logger.debug(`CRYPTOGRAPHIC_KEY_MATERIAL HKDF Secret: ${secretString}, Salt: ${saltString}, Info: ${infoString}, Length: ${length}`);

        return result;
    };

    abstract hmac(key: Uint8Array, data: Uint8Array): Uint8Array;
    static readonly hmac = (key: Uint8Array, data: Uint8Array): Uint8Array => Crypto.get().hmac(key, data);

    abstract sign(privateKey: JsonWebKey, data: Uint8Array | Uint8Array[], dsaEncoding?: CryptoDsaEncoding): Uint8Array;
    static readonly sign = (
        privateKey: JsonWebKey,
        data: Uint8Array | Uint8Array[],
        dsaEncoding?: CryptoDsaEncoding,
    ): Uint8Array => Crypto.get().sign(privateKey, data, dsaEncoding);

    abstract verify(
        publicKey: JsonWebKey,
        data: Uint8Array,
        signature: Uint8Array,
        dsaEncoding?: CryptoDsaEncoding,
    ): void;
    static readonly verify = (
        publicKey: JsonWebKey,
        data: Uint8Array,
        signature: Uint8Array,
        dsaEncoding?: CryptoDsaEncoding,
    ): void => Crypto.get().verify(publicKey, data, signature, dsaEncoding);

    abstract createKeyPair(): PrivateKey;
    static readonly createKeyPair = (): PrivateKey => Crypto.get().createKeyPair();
}

// Hook for testing frameworks
if (typeof MatterHooks !== "undefined") {
    MatterHooks.cryptoSetup?.(Crypto);
}
