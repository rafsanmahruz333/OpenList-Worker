
import test from "node:test"
import assert from "node:assert/strict"
import {
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync,
} from "node:crypto"
import { encryptV2 } from "./cipher-v2"

// Generate files using Crypt V2, but recover them
// WITHOUT calling decryptV2 or using CryptDriver.
function recoverWithNode(
  file: Uint8Array,
  password: string,
  vaultSalt: string,
): Buffer {
  const bytes = Buffer.from(file)
  const headerSize = 48
  const tagSize = 16

  if (bytes.length < headerSize + tagSize) {
    throw new Error("Invalid file length")
  }

  const header = bytes.subarray(0, headerSize)

  if (header.toString("utf8", 0, 8) !== "RFOSENC2") {
    throw new Error("Invalid V2 file header")
  }

  const chunkSize = header.readUInt32BE(32)
  const originalSizeBig = header.readBigUInt64BE(36)

  if (
    chunkSize !== 1024 * 1024 ||
    originalSizeBig > 8n * 1024n * 1024n
  ) {
    throw new Error("Unsupported V2 file")
  }

  if (!header.subarray(44, 48).every((byte) => byte === 0)) {
    throw new Error("Unsupported V2 flags")
  }

  const originalSize = Number(originalSizeBig)
  const chunks = Math.max(
    1,
    Math.ceil(originalSize / chunkSize),
  )

  if (
    bytes.length !==
    headerSize + originalSize + chunks * tagSize
  ) {
    throw new Error("Truncated or malformed file")
  }

  const keySalt = Buffer.concat([
    Buffer.from("RFOSENC2\0"),
    Buffer.from(vaultSalt, "utf8"),
    Buffer.from([0]),
    header.subarray(8, 24),
  ])

  const key = scryptSync(password, keySalt, 32, {
    N: 16384,
    r: 8,
    p: 1,
  })

  const plain = Buffer.alloc(originalSize)
  let position = headerSize

  for (let i = 0; i < chunks; i++) {
    const partSize = Math.min(
      chunkSize,
      originalSize - i * chunkSize,
    )

    const encryptedPart = bytes.subarray(
      position,
      position + partSize,
    )

    const authenticationTag = bytes.subarray(
      position + partSize,
      position + partSize + tagSize,
    )

    const nonce = Buffer.alloc(12)
    header.copy(nonce, 0, 24, 32)
    nonce.writeUInt32BE(i, 8)

    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      nonce,
    )

    decipher.setAAD(header)
    decipher.setAuthTag(authenticationTag)

    const recoveredPart = Buffer.concat([
      decipher.update(encryptedPart),
      decipher.final(),
    ])

    recoveredPart.copy(plain, i * chunkSize)
    position += partSize + tagSize
  }

  return plain
}

const pass = "dummy-password-only"
const salt = "dummy-salt-only"

test("independent recovery of 1.3 MB file", async () => {
  const original = randomBytes(1_321_229)
  const encrypted = await encryptV2(original, pass, salt)
  const recovered = recoverWithNode(encrypted, pass, salt)

  assert.deepEqual(recovered, original)
  assert.equal(
    createHash("sha256").update(recovered).digest("hex"),
    createHash("sha256").update(original).digest("hex"),
  )
})

test("independent recovery of empty file", async () => {
  const encrypted = await encryptV2(
    new Uint8Array(),
    pass,
    salt,
  )

  assert.equal(
    recoverWithNode(encrypted, pass, salt).length,
    0,
  )
})

test("wrong password is rejected", async () => {
  const encrypted = await encryptV2(
    randomBytes(512),
    pass,
    salt,
  )

  assert.throws(() =>
    recoverWithNode(encrypted, "wrong", salt),
  )
})

test("wrong salt is rejected", async () => {
  const encrypted = await encryptV2(
    randomBytes(512),
    pass,
    salt,
  )

  assert.throws(() =>
    recoverWithNode(encrypted, pass, "wrong"),
  )
})

test("tampered ciphertext is rejected", async () => {
  const encrypted = Buffer.from(
    await encryptV2(randomBytes(512), pass, salt),
  )

  encrypted[49] ^= 1

  assert.throws(() =>
    recoverWithNode(encrypted, pass, salt),
  )
})
