import {
  Hash,
  Signature,
  KeyGenConfiguration,
  KeyPair,
  PublicKey,
} from "@iroha2/crypto-core";
import { crypto } from "@iroha2/crypto-target-node";
import { bytesToHex as numBytesToHex } from "hada";

import express, { Express } from "express";
import {
  VersionedTransaction,
  Transaction,
  VecSignatureOfTransactionPayload,
  Signature as sign,
  PublicKey as publ,
  Logger,
  TransactionPayload,
} from "@iroha2/data-model";
import bodyParser from "body-parser";
import morgan from "morgan";

const app: Express = express();
const port = 8000;
app.use(bodyParser.json());
app.use(morgan("dev"));

//const mockedPrivateKey = '1ac802b12aee01389a3873f89e07d36d14e812ae993fe7fc7679e4243e5ed20f'

// Bytes utilities

function bytesToHex(bytes: Uint8Array): string {
  var array = [];

  for (var i = 0; i < bytes.byteLength; i++) {
    array[i] = bytes[i];
  }

  return numBytesToHex(array);
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

function FIXME_RANDOM_AES_256_GCM(
  hash: Uint8Array,
  password: string
): Uint8Array {
  //const arr = Array.from({ length: 40 }, () => Math.floor(Math.random() * 40));
  //console.log(arr);
  //return new Uint8Array(arr);

  return new Uint8Array([1, 2, 3, 4]);
}

function verify(sgn: Signature, payload: Uint8Array): boolean {
  try {
    sgn.verify(payload);
    return true;
  } catch {
    return false;
  }
}

function toHexString(byteArray: Iterable<number>) {
  return Array.from(byteArray, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});

//for routing you can do .get .post etc
app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.post("/signlogin", (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const hash = createHash(encodeStringAsUtf8Bytes(email + password));
  const seedBytes = FIXME_RANDOM_AES_256_GCM(hash, password);
  const keypair = createKeyPairWithSeed(seedBytes);
  const publicKey = keypair.publicKey();
  const signature = createEmailSignature(email, keypair);
  const request = buildRequestBody({
    email,
    signature,
    publicKey,
  });

  console.log("Request body is: %o", request);
  res.send(JSON.stringify(request));
});

app.post("/newuser", (req, res) => {
  const username = req.body.email;
  const password = req.body.password;

  const hash = createHash(encodeStringAsUtf8Bytes(username + password));
  const seedBytes = FIXME_RANDOM_AES_256_GCM(hash, password);
  const keypair = createKeyPairWithSeed(seedBytes);
  const publicKey = keypair.publicKey();

  /*
{
  "accountName": "foo",
  "authPublicKey": "string",
  "email": "foo@mail.com",
  "irohaPublicKey": "string",
  "salt": "string"
}
     */

  const response = {
    accountName: "testaccount",
    authPublicKey: publicKey,
    email: username,
    irohaPublicKey: password,
    salt: hash,
  };
  res.send(JSON.stringify(response));
});

app.post("/signdata", (req, res) => {
  const data2sign = req.body.data;
  const mockedPrivateKey = req.body.pkey;

  console.log(`Response data: %o`, data2sign);

  const keygenConfig = crypto
    .createKeyGenConfiguration()
    .useSeed(Uint8Array.from(Buffer.from(mockedPrivateKey, "hex")));
  const keyPair = crypto.generateKeyPairWithConfiguration(keygenConfig);

  const responseBytes = Uint8Array.from(Buffer.from(data2sign, "hex"));

  console.log(`Response data: %o`, data2sign);

  const { payload } = VersionedTransaction.fromBuffer(responseBytes).as("V1");

  console.log(`payload %o`, payload);

  const payloadBytes = responseBytes;
  const payloadHash = crypto.createHash(payloadBytes);
  const signature = crypto.createSignature(keyPair, payloadHash.bytes());
  const signatureBytes = signature.signatureBytes();

  let result;
  {
    const publicKey = keyPair.publicKey();
    const newSignedTransaction = Transaction({
      payload,
      signatures: VecSignatureOfTransactionPayload([
        sign({
          public_key: publ({
            digest_function: publicKey.digestFunction(),
            payload: publicKey.payload(),
          }),
          payload: signatureBytes,
        }),
      ]),
    });

    const encoded = VersionedTransaction.toBuffer(
      VersionedTransaction("V1", newSignedTransaction)
    );

    result = toHexString(encoded);
  }

  console.log(result);

  const verifyResult = verify(signature, payloadHash.bytes());

  res.send(result);
});

/**
 * **MAIN function**
 *
 * @returns encoded, but **signed** versioned transaction
 */
function signVersionedTx(
  encodedVersionedTransaction: Uint8Array,
  keypair: KeyPair
): Uint8Array {
  const tx = VersionedTransaction.fromBuffer(encodedVersionedTransaction);
  const { payload } = tx.as("V1");

  const signatureBytes = someBytesSignature(
    TransactionPayload.toBuffer(payload),
    keypair
  );
}

function someBytesSignature(bytes: Uint8Array, keypair: KeyPair): Uint8Array {
  const payloadHash = crypto.createHash(bytes);
  const signature = crypto.createSignature(keypair, payloadHash.bytes());
  const signatureBytes = signature.signatureBytes();

  payloadHash.free();
  signature.free();

  return signatureBytes;
}
