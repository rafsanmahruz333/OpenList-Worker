import test from "node:test"
import assert from "node:assert/strict"
import { createCipheriv, randomBytes, scryptSync } from "node:crypto"
import {
  decryptV2RemoteRange,
  inspectV2Remote,
  type CryptV2RangeReader,
} from "./cipher-v2-range"

const CHUNK = 1024 * 1024
const PASS = "a-demonstration-only-password"
const SALT = "a-demonstration-only-vault-salt"

// Independent native Node.js AES-256-GCM writer. This deliberately does not
// import encryptV2, so tests validate compatibility with the V2 wire format.
function makeNativeFixture(original: Uint8Array): Uint8Array {
  const header = Buffer.alloc(48)
  header.write("RFOSENC2", 0, "utf8")
  randomBytes(24).copy(header, 8)
  header.writeUInt32BE(CHUNK, 32)
  header.writeBigUInt64BE(BigInt(original.length), 36)
  const keySalt = Buffer.concat([
    Buffer.from("RFOSENC2\0"),
    Buffer.from(SALT),
    Buffer.from([0]),
    header.subarray(8, 24),
  ])
  const key = scryptSync(PASS, keySalt, 32, { N: 16384, r: 8, p: 1 })
  const parts: Buffer[] = [header]
  const count = Math.max(1, Math.ceil(original.length / CHUNK))
  for (let i = 0; i < count; i++) {
    const iv = Buffer.alloc(12)
    header.copy(iv, 0, 24, 32)
    iv.writeUInt32BE(i, 8)
    const encryptor = createCipheriv("aes-256-gcm", key, iv)
    encryptor.setAAD(header)
    const chunk = original.subarray(i * CHUNK, (i + 1) * CHUNK)
    parts.push(encryptor.update(chunk), encryptor.final(), encryptor.getAuthTag())
  }
  return new Uint8Array(Buffer.concat(parts))
}

function readerOf(data: Uint8Array) {
  const calls: [number, number][] = []
  const read: CryptV2RangeReader = async (start, end) => {
    calls.push([start, end])
    assert.ok(start >= 0 && end >= start && end < data.byteLength)
    return data.slice(start, end + 1)
  }
  return { read, calls }
}

const original = randomBytes(2 * CHUNK + 12345)
const encrypted = makeNativeFixture(original)

test("header size and multi-chunk offsets match the original V2 layout", async () => {
  const { read, calls } = readerOf(encrypted)
  const meta = await inspectV2Remote(read, encrypted.byteLength)
  assert.deepEqual(meta, {
    plainSize: original.length,
    encryptedSize: encrypted.length,
    chunkSize: CHUNK,
    chunkCount: 3,
  })
  assert.deepEqual(calls, [[0, 47]])
})

test("read first 101 bytes, fetching just header + first chunk", async () => {
  const { read, calls } = readerOf(encrypted)
  const result = await decryptV2RemoteRange(read, PASS, SALT, 0, 100, encrypted.length)
  assert.deepEqual(Buffer.from(result), original.subarray(0, 101))
  assert.deepEqual(calls, [[0, 47], [48, 48 + CHUNK + 16 - 1]])
})

test("cross 1 MiB chunk boundary and authenticate both chunks", async () => {
  const { read, calls } = readerOf(encrypted)
  const start = CHUNK - 4
  const end = CHUNK + 3
  const result = await decryptV2RemoteRange(read, PASS, SALT, start, end, encrypted.length)
  assert.deepEqual(Buffer.from(result), original.subarray(start, end + 1))
  assert.equal(calls.length, 3)
  assert.equal(calls[2][0], 48 + CHUNK + 16)
})

test("read final 10 bytes from last short chunk without earlier chunks", async () => {
  const { read, calls } = readerOf(encrypted)
  const end = original.length - 1
  const result = await decryptV2RemoteRange(read, PASS, SALT, end - 9, end, encrypted.length)
  assert.deepEqual(Buffer.from(result), original.subarray(end - 9))
  assert.equal(calls.length, 2)
  assert.equal(calls[1][0], 48 + 2 * (CHUNK + 16))
  assert.equal(calls[1][1], encrypted.length - 1)
})

test("2 MiB range does not read or decrypt the whole file", async () => {
  const { read, calls } = readerOf(encrypted)
  const start = 25
  const end = 2 * CHUNK + 18
  const result = await decryptV2RemoteRange(read, PASS, SALT, start, end, encrypted.length)
  assert.deepEqual(Buffer.from(result), original.subarray(start, end + 1))
  assert.equal(calls.length, 4) // header + 3 touched chunks
})

test("incorrect password and vault salt fail authentication", async () => {
  await assert.rejects(
    () => decryptV2RemoteRange(readerOf(encrypted).read, "incorrect", SALT, 0, 20),
    /authentication failed/i,
  )
  await assert.rejects(
    () => decryptV2RemoteRange(readerOf(encrypted).read, PASS, "incorrect", 0, 20),
    /authentication failed/i,
  )
})

test("tampered chunk, header, and incorrect file length are rejected", async () => {
  const brokenChunk = encrypted.slice()
  brokenChunk[48 + 17] ^= 1
  await assert.rejects(
    () => decryptV2RemoteRange(readerOf(brokenChunk).read, PASS, SALT, 0, 20),
    /authentication failed/i,
  )
  const brokenHeader = encrypted.slice()
  brokenHeader[24] ^= 1
  await assert.rejects(
    () => decryptV2RemoteRange(readerOf(brokenHeader).read, PASS, SALT, 0, 20),
    /authentication failed/i,
  )
  await assert.rejects(
    () => inspectV2Remote(readerOf(encrypted).read, encrypted.length - 1),
    /disagrees/i,
  )
})

test("reject invalid or dangerous ranges before fetching", async () => {
  const { read, calls } = readerOf(encrypted)
  for (const [start, end] of [
    [-1, 2], [10, 9], [0, Number.NaN], [0, 4 * CHUNK],
  ]) {
    await assert.rejects(
      () => decryptV2RemoteRange(read, PASS, SALT, start, end),
      /invalid or oversized/i,
    )
  }
  assert.equal(calls.length, 0)
  await assert.rejects(
    () => decryptV2RemoteRange(read, PASS, SALT, original.length, original.length),
    /exceeds file length/i,
  )
})

test("reject providers that ignore requested Range lengths", async () => {
  const wrongReader: CryptV2RangeReader = async () => encrypted
  await assert.rejects(
    () => decryptV2RemoteRange(wrongReader, PASS, SALT, 0, 10),
    /wrong byte range/i,
  )
})

test("empty-file size can be inspected but has no plaintext range", async () => {
  const empty = makeNativeFixture(new Uint8Array())
  const { read } = readerOf(empty)
  assert.deepEqual(await inspectV2Remote(read, empty.length), {
    plainSize: 0,
    encryptedSize: 64,
    chunkCount: 1,
    chunkSize: CHUNK,
  })
  await assert.rejects(
    () => decryptV2RemoteRange(read, PASS, SALT, 0, 0),
    /exceeds file length/i,
  )
})
