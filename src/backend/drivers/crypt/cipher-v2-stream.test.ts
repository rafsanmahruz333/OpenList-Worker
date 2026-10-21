import test from "node:test"
import assert from "node:assert/strict"
import { createCipheriv, randomBytes, scryptSync } from "node:crypto"
import { createV2RemoteStream } from "./cipher-v2-stream"
import type { CryptV2RangeReader } from "./cipher-v2-range"

const MIB = 1024 * 1024
const PASSWORD = "disposable-large-stream-demo-password"
const SALT = "disposable-large-stream-demo-salt"

// Produce an independent, native-Node encryption fixture (not encryptV2).
function makeFixture(original: Uint8Array): Uint8Array {
  const header = Buffer.alloc(48)
  header.write("RFOSENC2", 0, "utf8")
  randomBytes(24).copy(header, 8)
  header.writeUInt32BE(MIB, 32)
  header.writeBigUInt64BE(BigInt(original.length), 36)
  const key = scryptSync(PASSWORD, Buffer.concat([
    Buffer.from("RFOSENC2\0"), Buffer.from(SALT), Buffer.from([0]),
    header.subarray(8, 24),
  ]), 32, { N: 16384, r: 8, p: 1 })
  const chunks = Math.max(1, Math.ceil(original.length / MIB))
  const parts: Buffer[] = [header]
  for (let i = 0; i < chunks; i++) {
    const iv = Buffer.alloc(12)
    header.copy(iv, 0, 24, 32)
    iv.writeUInt32BE(i, 8)
    const cipher = createCipheriv("aes-256-gcm", key, iv)
    cipher.setAAD(header)
    const source = original.subarray(i * MIB, (i + 1) * MIB)
    parts.push(cipher.update(source), cipher.final(), cipher.getAuthTag())
  }
  return new Uint8Array(Buffer.concat(parts))
}

function makeReader(encrypted: Uint8Array) {
  const requests: Array<[number, number]> = []
  let bytesServed = 0
  const read: CryptV2RangeReader = async (start, end) => {
    assert.ok(start >= 0 && end < encrypted.byteLength && start <= end)
    requests.push([start, end])
    bytesServed += end - start + 1
    return encrypted.slice(start, end + 1)
  }
  return { read, requests, get bytesServed() { return bytesServed } }
}

const original = randomBytes(11 * MIB + 2345) // Deliberately >8 MiB.
const encrypted = makeFixture(original)

test("11 MiB+ file streams completely and matches independent original", async () => {
  const remote = makeReader(encrypted)
  const result = await createV2RemoteStream(remote.read, PASSWORD, SALT, {
    expectedEncryptedSize: encrypted.byteLength,
  })
  assert.equal(result.metadata.plainSize, original.length)
  assert.equal(result.metadata.chunkCount, 12)
  const recovered = new Uint8Array(await new Response(result.stream).arrayBuffer())
  assert.deepEqual(Buffer.from(recovered), original)
  assert.ok(remote.requests.every(([a, b]) => b - a + 1 <= MIB + 16))
})

test("reads near the end without downloading preceding chunks", async () => {
  const remote = makeReader(encrypted)
  const start = original.byteLength - 123
  const result = await createV2RemoteStream(remote.read, PASSWORD, SALT, {
    start, expectedEncryptedSize: encrypted.byteLength,
  })
  const recovered = new Uint8Array(await new Response(result.stream).arrayBuffer())
  assert.deepEqual(Buffer.from(recovered), original.subarray(start))
  assert.ok(remote.bytesServed < MIB, "should not fetch earlier full chunks")
})

test("range across chunk boundary matches byte-for-byte", async () => {
  const remote = makeReader(encrypted)
  const start = 9 * MIB - 9
  const end = 9 * MIB + 37
  const result = await createV2RemoteStream(remote.read, PASSWORD, SALT, {
    start, end, expectedEncryptedSize: encrypted.byteLength,
  })
  const recovered = new Uint8Array(await new Response(result.stream).arrayBuffer())
  assert.deepEqual(Buffer.from(recovered), original.subarray(start, end + 1))
})

test("no encrypted body is read until consumer requests stream data", async () => {
  const remote = makeReader(encrypted)
  const result = await createV2RemoteStream(remote.read, PASSWORD, SALT, {
    expectedEncryptedSize: encrypted.byteLength,
  })
  assert.deepEqual(remote.requests, [[0, 47]])
  const reader = result.stream.getReader()
  const first = await reader.read()
  assert.equal(first.done, false)
  assert.equal(first.value?.byteLength, 3 * MIB)
  assert.ok(Buffer.from(first.value!).equals(original.subarray(0, 3 * MIB)))
  await reader.cancel()
  assert.equal(remote.requests.length, 5) // initial header + repeated header + 3 chunks
})

test("bad password fails before any plaintext can be read", async () => {
  const remote = makeReader(encrypted)
  const result = await createV2RemoteStream(remote.read, "wrong", SALT, {
    expectedEncryptedSize: encrypted.byteLength,
  })
  await assert.rejects(() => new Response(result.stream).arrayBuffer(), /authentication failed/i)
})

test("tampered later chunk aborts whole streamed read", async () => {
  const broken = encrypted.slice()
  broken[48 + 5 * (MIB + 16) + 15] ^= 1
  const remote = makeReader(broken)
  const result = await createV2RemoteStream(remote.read, PASSWORD, SALT, {
    expectedEncryptedSize: broken.byteLength,
  })
  await assert.rejects(() => new Response(result.stream).arrayBuffer(), /authentication failed/i)
})

test("incorrect encrypted metadata is rejected", async () => {
  const remote = makeReader(encrypted)
  await assert.rejects(
    () => createV2RemoteStream(remote.read, PASSWORD, SALT, {
      expectedEncryptedSize: encrypted.byteLength - 1,
    }), /disagrees/i,
  )
})

test("invalid ranges and enormous read windows are rejected", async () => {
  const remote = makeReader(encrypted)
  await assert.rejects(() => createV2RemoteStream(remote.read, PASSWORD, SALT, {
    windowBytes: 5 * MIB,
  }), /read window/i)
  await assert.rejects(() => createV2RemoteStream(remote.read, PASSWORD, SALT, {
    start: original.length, end: original.length,
  }), /stream range/i)
  await assert.rejects(() => createV2RemoteStream(remote.read, PASSWORD, SALT, {
    start: 12, end: 11,
  }), /stream range/i)
})

test("empty file must use existing authenticated full-file decoder", async () => {
  const empty = makeFixture(new Uint8Array())
  await assert.rejects(() => createV2RemoteStream(
    makeReader(empty).read, PASSWORD, SALT,
    { expectedEncryptedSize: empty.byteLength },
  ), /empty file/i)
})
