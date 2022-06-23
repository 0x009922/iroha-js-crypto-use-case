import { KeyPair } from "@iroha2/crypto-core";
import { crypto } from "@iroha2/crypto-target-node";
import {
  VersionedTransaction,
  TransactionPayload,
  Transaction,
  VecSignatureOfTransactionPayload,
  Signature,
  PublicKey,
} from "@iroha2/data-model";

/**
 * **MAIN function**
 *
 * @returns encoded, but **signed** versioned transaction
 */
function sign_versioned_tx(
  encodedVersionedTransaction: Uint8Array,
  keypair: KeyPair
): Uint8Array {
  const tx = VersionedTransaction.fromBuffer(encodedVersionedTransaction);
  const { payload } = tx.as("V1");

  const signature = sign_bytes_with_keypair(
    TransactionPayload.toBuffer(payload),
    keypair
  );

  const signedTx = VersionedTransaction(
    "V1",
    Transaction({
      payload,
      signatures: VecSignatureOfTransactionPayload([signature]),
    })
  );

  return VersionedTransaction.toBuffer(signedTx);
}

function sign_bytes_with_keypair(
  bytes: Uint8Array,
  keypair: KeyPair
): Signature {
  const payloadHash = crypto.createHash(bytes);
  console.log("before create signature", {
    pub: to_hex(keypair.publicKey().payload()),
    priv: to_hex(keypair.privateKey().payload()),
  });
  const signatureCrypto = crypto.createSignature(keypair, payloadHash.bytes());
  console.log("signature ok!");
  const signatureBytes = signatureCrypto.signatureBytes();

  const pk = signatureCrypto.publicKey();
  const signature = Signature({
    payload: signatureBytes,
    public_key: PublicKey({
      digest_function: pk.digestFunction(),
      payload: pk.payload(),
    }),
  });

  for (const x of [payloadHash, signatureCrypto, pk]) {
    x.free();
  }

  return signature;
}

/**
 * Note: creates keys with ed25519 digest function
 */
function key_pair_from_hex_pair(pubHex: string, privHex: string): KeyPair {
  const ED25519_DIGEST = "ed25519";
  const MAGIC_ED25519_MULTIHASH_PREFIX = "ed0120";

  const pub = crypto.createPublicKeyFromMultihash(
    crypto.createMultihashFromBytes(
      from_hex(MAGIC_ED25519_MULTIHASH_PREFIX + pubHex)
    )
  );

  const priv = crypto.createPrivateKeyFromJsKey({
    payload:
      // please don't ask me why private key payload should have pub key hex too
      privHex + pubHex,
    digestFunction: ED25519_DIGEST,
  });

  console.log("Ensure that keys payloads are OK", {
    pub: to_hex(pub.payload()),
    priv: to_hex(priv.payload()),
  });

  const keypair = crypto.createKeyPairFromKeys(pub, priv);

  return keypair;
}

function from_hex(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function to_hex(bytes: Uint8Array): string {
  return [...bytes].map((x) => x.toString(16).padStart(2, "0")).join("");
}

// ================================

// Our input data
const PUB_KEY_HEX = `0851a1fa7e3f04a657299263e119975be4ab0d33631ec6ad4bd5b5e77594310e`;
const PRIV_KEY_HEX = `1ac802b12aee01389a3873f89e07d36d14e812ae993fe7fc7679e4243e5ed20f`;
const ENCODED_VERSIONED_TX = `0114616c69636528776f6e6465726c616e640028000d0905243132372e302e302e3130636f6e747269627574696f6e030000090d0803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d040869640d03243132372e302e302e31090d0803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d040866740d0003000000090d0803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d040c6f72670d03085553090d0803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d040c6473740d03085a41090d0803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d040c7374730d0000000000090d0803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d040865640d0085ce3801090d0803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d040874730d0334313635353732373738353833360b0d0e8063616e5f7365745f6b65795f76616c75655f696e5f757365725f617373657473042061737365745f69640803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d08010c626f621461646d696e000d0907786f757464617465645f636f6e747269627574696f6e3132372e302e302e310004090d0803243132372e302e302e3130636f6e747269627574696f6e14616c69636528776f6e6465726c616e640d04546f757464617465645f636f6e747269627574696f6e0d020101010000000c626f621461646d696e0201ae66b062000000000000000000006c07118181010000005c26050000000001bb2889be0000`;

// First of all - preparing our key pair
const KEY_PAIR = key_pair_from_hex_pair(PUB_KEY_HEX, PRIV_KEY_HEX);

// Ok, now let's sign our tx
const signedTx = sign_versioned_tx(from_hex(ENCODED_VERSIONED_TX), KEY_PAIR);

// Voila!
console.log(to_hex(signedTx));
