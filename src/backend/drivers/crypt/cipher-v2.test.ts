
import test from "node:test"
import assert from "node:assert/strict"
import { randomBytes } from "node:crypto"
import { encryptV2, decryptV2 } from "./cipher-v2"

const PASSWORD = "test-password-not-real"
const SALT = "test-salt-not-real"
const HEADER_SIZE = 48
const TAG_SIZE = 16
const CHUNK_SIZE = 1024 * 1024

test("small file encrypts and decrypts correctly", async () => {
  const original = randomBytes(1024)
  const encrypted = await encryptV2(original, PASSWORD, SALT)
  const recovered = await decryptV2(encrypted, PASSWORD, SALT)

  assert.deepEqual(Buffer.from(recovered), original)
  assert.equal(encrypted.length, original.length + HEADER_SIZE + TAG_SIZE)
})

test("empty file is supported", async () => {
  const encrypted = await encryptV2(new Uint8Array(), PASSWORD, SALT)
  const recovered = await decryptV2(encrypted, PASSWORD, SALT)

  assert.equal(encrypted.length, HEADER_SIZE + TAG_SIZE)
  assert.equal(recovered.length, 0)
})

test("wrong password is rejected", async () => {
  const encrypted = await encryptV2(randomBytes(128), PASSWORD, SALT)

  await assert.rejects(
    () => decryptV2(encrypted, "wrong-password", SALT),
    /authentication failed/i,
  )
})

test("wrong salt is rejected", async () => {
  const encrypted = await encryptV2(randomBytes(128), PASSWORD, SALT)

  await assert.rejects(
    () => decryptV2(encrypted, PASSWORD, "wrong-salt"),
    /authentication failed/i,
  )
})

test("modified ciphertext is detected", async () => {
  const encrypted = await encryptV2(randomBytes(128), PASSWORD, SALT)
  const damaged = encrypted.slice()
  damaged[HEADER_SIZE + 10] ^= 1

  await assert.rejects(
    () => decryptV2(damaged, PASSWORD, SALT),
    /authentication failed/i,
  )
})

test("modified header is detected", async () => {
  const encrypted = await encryptV2(randomBytes(128), PASSWORD, SALT)
  const damaged = encrypted.slice()
  damaged[24] ^= 1

  await assert.rejects(
    () => decryptV2(damaged, PASSWORD, SALT),
    /authentication failed/i,
  )
})

test("truncated file is rejected", async () => {
  const encrypted = await encryptV2(randomBytes(128), PASSWORD, SALT)

  await assert.rejects(
    () => decryptV2(encrypted.subarray(0, -1), PASSWORD, SALT),
    /truncat|malformed|length mismatch/i,
  )
})

test("multiple chunks encrypt and decrypt correctly", async () => {
  const original = randomBytes(2 * CHUNK_SIZE + 71)
  const encrypted = await encryptV2(original, PASSWORD, SALT)
  const recovered = await decryptV2(encrypted, PASSWORD, SALT)

  assert.deepEqual(Buffer.from(recovered), original)
  assert.equal(
    encrypted.length,
    original.length + HEADER_SIZE + 3 * TAG_SIZE,
  )

  const damaged = encrypted.slice()
  damaged[HEADER_SIZE + CHUNK_SIZE + TAG_SIZE + 7] ^= 1

  await assert.rejects(
    () => decryptV2(damaged, PASSWORD, SALT),
    /authentication failed/i,
  )
})

test("encrypting twice produces different ciphertext", async () => {
  const original = randomBytes(64)
  const first = await encryptV2(original, PASSWORD, SALT)
  const second = await encryptV2(original, PASSWORD, SALT)

  assert.notDeepEqual(first, second)
  assert.deepEqual(
    Buffer.from(await decryptV2(first, PASSWORD, SALT)),
    original,
  )
  assert.deepEqual(
    Buffer.from(await decryptV2(second, PASSWORD, SALT)),
    original,
  )
})

test("unknown file format is rejected", async () => {
  const encrypted = await encryptV2(randomBytes(64), PASSWORD, SALT)
  const damaged = encrypted.slice()
  damaged[0] ^= 1

  await assert.rejects(
    () => decryptV2(damaged, PASSWORD, SALT),
    /Not a Crypt V2 file/i,
  )
})

test("files larger than 8 MiB are rejected by prototype", async () => {
  await assert.rejects(
    () => encryptV2(new Uint8Array(8 * CHUNK_SIZE + 1), PASSWORD, SALT),
    /8 MiB/,
  )
})
