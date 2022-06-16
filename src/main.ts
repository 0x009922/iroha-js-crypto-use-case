import {
  Hash,
  Signature,
  KeyGenConfiguration,
  KeyPair,
  PublicKey,
} from "@iroha2/crypto-core";
import { crypto } from "@iroha2/crypto-target-node";
import { bytesToHex as numBytesToHex } from "hada";
import fs from "fs/promises";

// Bytes utilities

function bytesToHex(bytes: Uint8Array): string {
  return numBytesToHex([...bytes]);
}

const stringEncoder = new TextEncoder();
function encodeStringAsUtf8Bytes(val: string): Uint8Array {
  return stringEncoder.encode(val);
}

// Crypto utilities

function createHash(payload: Uint8Array): Uint8Array {
  const hash = crypto.createHash(payload);
  const bytes = hash.bytes();
  hash.free();
  return bytes;
}

function createKeyPairWithSeed(seed: Uint8Array): KeyPair {
  const config = crypto.createKeyGenConfiguration().useSeed(seed);
  const keypair = crypto.generateKeyPairWithConfiguration(config);
  return keypair;
}

function createEmailSignature(email: string, keypair: KeyPair): Signature {
  const emailBytes = encodeStringAsUtf8Bytes(email);
  const signature = crypto.createSignature(keypair, emailBytes);
  return signature;
}

function buildRequestBody(params: {
  email: string;
  signature: Signature;
  publicKey: PublicKey;
}): {
  email: string;
  signature: string;
  publicKey: string;
} {
  return {
    email: params.email,
    signature: bytesToHex(params.signature.signatureBytes()),
    publicKey: bytesToHex(params.publicKey.payload()),
  };
}

function FAKE_AES_256_GCM(hash: Uint8Array, password: string): Uint8Array {
  return new Uint8Array([
    // some bytes
    1, 2, 3, 4,
  ]);
}

// Use-case flow

async function main() {
  // "2. Web application computes the hash of credentials and stores it in the storage"
  const email = "some email";
  const password = "some password";
  // hashing
  const hash = createHash(encodeStringAsUtf8Bytes(email + password));

  // -- skipping part of hash storing

  // "3. Web application restore users authentication keypair
  //     in the same manner as described above"
  // making seed with AES
  const seedBytes = FAKE_AES_256_GCM(hash, password);
  // making key pair
  const keypair = createKeyPairWithSeed(seedBytes);

  // "4. Web application sends a request to the backend's authentication server to log in.
  //     In the request body there are:"
  // we have some key pair (here just null for demo)
  // extracting pub key from keypair
  const publicKey = keypair.publicKey();
  // making signature
  const signature = createEmailSignature(email, keypair);
  // building request body
  const request = buildRequestBody({
    email,
    signature,
    publicKey,
  });
  // now you could send it to a back-end. or just log out.
  console.log("Request body is: %o", request);
}

main().catch((err) => {
  console.error("fatal", err);
  process.exit(1);
});
