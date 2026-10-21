import test from "node:test"
import assert from "node:assert/strict"
import { randomBytes, createHash } from "node:crypto"
import { newV2UploadHeader } from "../../drivers/crypt/cipher-v2-upload"
import {
  getV2UploadLayout, getV2ChunkLayout, createImmutableV2Session,
  checkImmutableChunkReceipt, nextGooglePutWindow, GDRIVE_ALIGNMENT_BYTES,
} from "./cryptv2-upload-plan"

const MIB = 1024 * 1024
const GIB = 1024 ** 3
const sha = (data: Uint8Array) => createHash("sha256").update(data).digest("hex")

test("20 GiB file plans exact encrypted length without allocation", () => {
  const layout = getV2UploadLayout(20 * GIB)
  assert.equal(layout.chunkCount, 20 * 1024)
  assert.equal(layout.encryptedSize, 48 + 20 * GIB + layout.chunkCount * 16)
})

test("empty file has one tag and a 64-byte ciphertext", () => {
  assert.deepEqual(getV2UploadLayout(0), { plainSize: 0, encryptedSize: 64, chunkCount: 1 })
  assert.deepEqual(getV2ChunkLayout(0, 0), {
    index: 0, plainStart: 0, plainLength: 0, encryptedStart: 48, encryptedLength: 16,
  })
})

test("last partial chunk has exact offsets and tag", () => {
  assert.deepEqual(getV2ChunkLayout(2 * MIB + 12345, 2), {
    index: 2, plainStart: 2 * MIB, plainLength: 12345,
    encryptedStart: 48 + 2 * (MIB + 16), encryptedLength: 12361,
  })
})

test("layout rejects unsafe or negative lengths and chunk indices", () => {
  for (const n of [-1, NaN, Infinity, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => getV2UploadLayout(n))
  }
  assert.throws(() => getV2ChunkLayout(1, 1), /chunk index/i)
})

test("immutable session persists header, owner and exact layout", () => {
  const size = 20 * GIB
  const header = newV2UploadHeader(size)
  const session = createImmutableV2Session({
    sessionId: "upload_session_abc123", ownerId: 7,
    path: "/Secure-Test/video.mp4", header, plainSize: size, createdAtMs: 10,
  })
  assert.equal(session.headerHex, Buffer.from(header).toString("hex"))
  assert.equal(session.ownerId, 7)
  assert.equal(session.chunkCount, 20480)
})

test("session rejects altered file header or plaintext length", () => {
  const header = newV2UploadHeader(2 * MIB)
  assert.throws(() => createImmutableV2Session({
    sessionId: "upload_session_abc123", ownerId: 7,
    path: "/Secure-Test/test.dat", header, plainSize: MIB, createdAtMs: 10,
  }), /does not match/i)
  const altered = Uint8Array.from(header)
  altered[44] = 1
  assert.throws(() => createImmutableV2Session({
    sessionId: "upload_session_abc123", ownerId: 7,
    path: "/Secure-Test/test.dat", header: altered, plainSize: 2 * MIB, createdAtMs: 10,
  }))
})

test("session rejects invalid identifiers, owner and traversal", () => {
  const base = { sessionId: "upload_session_abc123", ownerId: 7,
    path: "/Secure-Test/video.mp4", header: newV2UploadHeader(MIB), plainSize: MIB, createdAtMs: 10 }
  assert.throws(() => createImmutableV2Session({ ...base, sessionId: "short" }))
  assert.throws(() => createImmutableV2Session({ ...base, ownerId: -1 }))
  assert.throws(() => createImmutableV2Session({ ...base, path: "/Secure-Test/../other" }))
})

test("identical retry is allowed but a different digest is rejected", () => {
  const digest = sha(randomBytes(32))
  const differentDigest = sha(randomBytes(32))
  assert.equal(checkImmutableChunkReceipt(undefined, 5, digest), "reserve-new")
  assert.equal(checkImmutableChunkReceipt({ index: 5, digestSha256: digest, status: "reserved" }, 5, digest), "retry-same")
  assert.equal(checkImmutableChunkReceipt({ index: 5, digestSha256: digest, status: "acknowledged" }, 5, digest), "already-acknowledged")
  assert.throws(() => checkImmutableChunkReceipt({ index: 5, digestSha256: digest, status: "reserved" }, 5, differentDigest), /conflicting retry/i)
  assert.throws(() => checkImmutableChunkReceipt({ index: 4, digestSha256: digest, status: "reserved" }, 5, digest), /conflicting retry/i)
})

test("incorrect digest is rejected before a reservation", () => {
  assert.throws(() => checkImmutableChunkReceipt(undefined, 0, "not a digest"), /digest/i)
  assert.throws(() => checkImmutableChunkReceipt(undefined, -1, "a".repeat(64)), /chunk index/i)
})

test("Google Drive PUT windows are aligned except the final one", () => {
  const encryptedSize = getV2UploadLayout(20 * GIB).encryptedSize
  let offset = 0, total = 0, putCount = 0
  while (offset < encryptedSize) {
    const w = nextGooglePutWindow(encryptedSize, offset, 8 * MIB)
    assert.equal(w.start, offset)
    assert.equal(w.end, w.start + w.length - 1)
    if (!w.isFinal) assert.equal(w.length % GDRIVE_ALIGNMENT_BYTES, 0)
    total += w.length
    offset = w.end + 1
    putCount++
  }
  assert.equal(total, encryptedSize)
  assert.ok(putCount > 2500 && putCount < 3000)
})

test("Google Drive rejects unaligned offsets and too-small windows", () => {
  assert.throws(() => nextGooglePutWindow(10 * MIB, 1), /offset/i)
  assert.throws(() => nextGooglePutWindow(10 * MIB, 0, 10), /window/i)
  assert.throws(() => nextGooglePutWindow(10 * MIB, 10 * MIB), /offset/i)
})
