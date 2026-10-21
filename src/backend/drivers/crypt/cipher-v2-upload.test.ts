import test from "node:test"
import assert from "node:assert/strict"
import { createDecipheriv, randomBytes, scryptSync } from "node:crypto"
import {
  newV2UploadHeader,
  newV2UploadEncryptor,
  openV2UploadEncryptor,
} from "./cipher-v2-upload"

const MIB = 1024 * 1024
const PASSWORD = "disposable-upload-test-password"
const SALT = "disposable-upload-test-vault-salt"

// Independent native Node.js decoder; not the CryptV2 decrypt implementation.
function decodeIndependently(encrypted: Uint8Array): Buffer {
  const data = Buffer.from(encrypted)
  const header = data.subarray(0, 48)
  assert.equal(header.toString("utf8", 0, 8), "RFOSENC2")
  assert.equal(header.readUInt32BE(32), MIB)
  const originalSize = Number(header.readBigUInt64BE(36))
  const key = scryptSync(PASSWORD, Buffer.concat([
    Buffer.from("RFOSENC2\0"), Buffer.from(SALT), Buffer.from([0]),
    header.subarray(8, 24),
  ]), 32, { N: 16384, r: 8, p: 1 })
  const count = Math.max(1, Math.ceil(originalSize / MIB))
  let position = 48
  const result: Buffer[] = []
  for (let i = 0; i < count; i++) {
    const bytes = Math.min(MIB, originalSize - i * MIB)
    const chunk = data.subarray(position, position + bytes)
    const tag = data.subarray(position + bytes, position + bytes + 16)
    const iv = Buffer.alloc(12)
    header.copy(iv, 0, 24, 32)
    iv.writeUInt32BE(i, 8)
    const cipher = createDecipheriv("aes-256-gcm", key, iv)
    cipher.setAAD(header)
    cipher.setAuthTag(tag)
    result.push(cipher.update(chunk), cipher.final())
    position += bytes + 16
  }
  assert.equal(position, data.length)
  return Buffer.concat(result)
}

async function buildViaParts(original: Uint8Array): Promise<Uint8Array> {
  const session = await newV2UploadEncryptor(original.length, PASSWORD, SALT)
  const pieces: Uint8Array[] = [session.header]
  for (let i = 0; i < session.metadata.chunkCount; i++) {
    pieces.push(await session.encryptChunk(i, original.subarray(i * MIB, (i + 1) * MIB)))
  }
  const combined = Buffer.concat(pieces.map(piece => Buffer.from(piece)))
  assert.equal(combined.length, session.metadata.encryptedSize)
  return combined
}

test("small file encodes into existing RFOSENC2 wire format", async () => {
  const original = randomBytes(111)
  assert.deepEqual(decodeIndependently(await buildViaParts(original)), original)
})

test("multi-chunk file encrypts and recovers byte-for-byte", async () => {
  const original = randomBytes(2 * MIB + 12345)
  assert.deepEqual(decodeIndependently(await buildViaParts(original)), original)
})

test("large 12 MiB+ file encrypts and independently recovers", async () => {
  const original = randomBytes(12 * MIB + 12345)
  assert.deepEqual(decodeIndependently(await buildViaParts(original)), original)
})

test("header can reconstruct an encryptor without changing file format", async () => {
  const input = randomBytes(MIB + 77)
  const header = newV2UploadHeader(input.length)
  const pieces: Uint8Array[] = [header]
  for (let i = 0; i < 2; i++) {
    const session = await openV2UploadEncryptor(header, PASSWORD, SALT)
    pieces.push(await session.encryptChunk(i, input.subarray(i * MIB, (i + 1) * MIB)))
  }
  assert.deepEqual(decodeIndependently(Buffer.concat(pieces)), input)
})

test("empty file still has one authenticated tag", async () => {
  const encrypted = await buildViaParts(new Uint8Array())
  assert.equal(encrypted.byteLength, 64)
  assert.equal(decodeIndependently(encrypted).length, 0)
})

test("two new headers use independent random salts and nonces", async () => {
  const a = newV2UploadHeader(10)
  const b = newV2UploadHeader(10)
  assert.notDeepEqual(a, b)
})

test("invalid file sizes are rejected", () => {
  for (const size of [-1, 1.25, Number.NaN, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => newV2UploadHeader(size), /invalid|format|safe/i)
  }
})

test("wrong part indices and sizes are rejected", async () => {
  const session = await newV2UploadEncryptor(MIB + 17, PASSWORD, SALT)
  await assert.rejects(() => session.encryptChunk(-1, new Uint8Array()), /index/i)
  await assert.rejects(() => session.encryptChunk(2, new Uint8Array()), /index/i)
  await assert.rejects(() => session.encryptChunk(0, new Uint8Array(3)), /size/i)
  await assert.rejects(() => session.encryptChunk(1, new Uint8Array(16)), /size/i)
})

test("same encryptor rejects nonce reuse at the same chunk index", async () => {
  const session = await newV2UploadEncryptor(9, PASSWORD, SALT)
  await session.encryptChunk(0, new Uint8Array(9))
  await assert.rejects(
    () => session.encryptChunk(0, new Uint8Array(9).fill(1)),
    /nonce/i,
  )
})

test("tampered ciphertext cannot be decrypted", async () => {
  const encrypted = await buildViaParts(randomBytes(45))
  encrypted[48] ^= 1
  assert.throws(() => decodeIndependently(encrypted), /auth|unsupported/i)
})

test("malformed header fails before encryption", async () => {
  const header = newV2UploadHeader(12)
  header[0] ^= 1
  await assert.rejects(() => openV2UploadEncryptor(header, PASSWORD, SALT), /magic/i)
})
