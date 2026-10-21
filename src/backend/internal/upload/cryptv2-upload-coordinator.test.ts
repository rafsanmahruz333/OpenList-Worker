import test from "node:test"
import assert from "node:assert/strict"
import { createHash, randomBytes } from "node:crypto"
import { newV2UploadHeader } from "../../drivers/crypt/cipher-v2-upload"
import { createImmutableV2Session } from "./cryptv2-upload-plan"
import { DurableV2UploadCoordinator, type DurableV2CoordinatorStorage } from "./cryptv2-upload-coordinator"

const MiB = 1024 * 1024
const hash = (s: string) => createHash("sha256").update(s).digest("hex")

/** Test-only simulation of synchronous SQLite-backed DO KV + rollback. */
class TestSqliteDurableStorage implements DurableV2CoordinatorStorage {
  private db = new Map<string, unknown>()
  readonly kv = {
    get: <T>(key: string): T | undefined => this.db.get(key) as T | undefined,
    put: (key: string, value: unknown): void => { this.db.set(key, structuredClone(value)) },
  }
  transactionSync<T>(callback: () => T): T {
    const before = structuredClone(this.db)
    try { return callback() }
    catch (err) { this.db = before; throw err }
  }
  get storedEntries() { return this.db.size }
}

function makeSession(size = 2 * MiB + 123, sessionId = "upload_session_abcdef") {
  return createImmutableV2Session({
    sessionId, ownerId: 42, path: "/Secure-Test/movie.mp4",
    header: newV2UploadHeader(size), plainSize: size, createdAtMs: 1000,
  })
}

test("creates a durable upload session and reads authenticated-owner status", () => {
  const db = new TestSqliteDurableStorage(), c = new DurableV2UploadCoordinator(db)
  const session = makeSession()
  const state = c.start(session)
  assert.deepEqual(state.immutable, session)
  assert.equal(state.phase, "receiving")
  assert.equal(state.acknowledgedChunks, 0)
  assert.equal(state.remoteCommittedBytes, 0)
  assert.deepEqual(c.status(session.sessionId, 42), state)
  assert.equal(db.storedEntries, 1)
})

test("session creation is idempotent but never silently replaces header", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage())
  const a = makeSession(), b = makeSession()
  assert.deepEqual(c.start(a), c.start(a))
  assert.throws(() => c.start(b), /different immutable metadata/)
  assert.equal(c.status(a.sessionId, 42).immutable.headerHex, a.headerHex)
})

test("session rejects forged sizes or metadata even with a valid header", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage())
  const s = makeSession()
  assert.throws(() => c.start({ ...s, chunkCount: s.chunkCount + 1 }), /inconsistent/i)
  assert.throws(() => c.start({ ...s, plainSize: 1 }), /does not match/i)
  assert.throws(() => c.start({ ...s, headerHex: "x" }), /header/i)
})

test("reservations survive coordinator reconstruction, including across chunks", () => {
  const db = new TestSqliteDurableStorage(), s = makeSession()
  const a = new DurableV2UploadCoordinator(db); a.start(s)
  assert.equal(a.reserveChunk(s.sessionId, 42, 0, hash("chunk0")), "reserve-new")
  const b = new DurableV2UploadCoordinator(db)
  assert.equal(b.reserveChunk(s.sessionId, 42, 0, hash("chunk0")), "retry-same")
  assert.equal(b.reserveChunk(s.sessionId, 42, 1, hash("chunk1")), "reserve-new")
  assert.equal(db.storedEntries, 3)
})

test("same nonce cannot be reserved with different plaintext on any instance", () => {
  const db = new TestSqliteDurableStorage(), s = makeSession()
  const a = new DurableV2UploadCoordinator(db), b = new DurableV2UploadCoordinator(db)
  a.start(s)
  a.reserveChunk(s.sessionId, 42, 0, hash("one"))
  assert.throws(() => b.reserveChunk(s.sessionId, 42, 0, hash("different")), /conflicting retry/i)
  assert.equal(a.reserveChunk(s.sessionId, 42, 0, hash("one")), "retry-same")
})

test("owner isolation applies to status, reservation, progress, and abort", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage()), s = makeSession()
  c.start(s)
  assert.throws(() => c.status(s.sessionId, 99), /not found/i)
  assert.throws(() => c.reserveChunk(s.sessionId, 99, 0, hash("x")), /not found/i)
  assert.throws(() => c.confirmRemoteOffset(s.sessionId, 99, 262144), /not found/i)
  assert.throws(() => c.abort(s.sessionId, 99), /not found/i)
})

test("rejects malformed SHA-256 and chunk outside file without durable write", () => {
  const db = new TestSqliteDurableStorage(), c = new DurableV2UploadCoordinator(db)
  const s = makeSession(MiB + 1); c.start(s)
  assert.throws(() => c.reserveChunk(s.sessionId, 42, 0, "abc"), /digest/i)
  assert.throws(() => c.reserveChunk(s.sessionId, 42, 2, hash("x")), /chunk index/i)
  assert.equal(db.storedEntries, 1)
})

test("chunk acknowledgements increment only once and reject conflicting digests", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage()), s = makeSession()
  c.start(s)
  assert.throws(() => c.acknowledgeChunk(s.sessionId, 42, 0, hash("one")), /not reserved/i)
  c.reserveChunk(s.sessionId, 42, 0, hash("one"))
  assert.equal(c.acknowledgeChunk(s.sessionId, 42, 0, hash("one")), "acknowledged")
  assert.equal(c.acknowledgeChunk(s.sessionId, 42, 0, hash("one")), "already-acknowledged")
  assert.throws(() => c.acknowledgeChunk(s.sessionId, 42, 0, hash("two")), /conflicting/i)
  assert.equal(c.status(s.sessionId, 42).acknowledgedChunks, 1)
})

test("remote offset is monotonic, Google-aligned, and supports unaligned final", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage()), s = makeSession()
  c.start(s)
  assert.equal(c.confirmRemoteOffset(s.sessionId, 42, 262144), 262144)
  assert.equal(c.confirmRemoteOffset(s.sessionId, 42, 262144), 262144)
  assert.throws(() => c.confirmRemoteOffset(s.sessionId, 42, 1), /offset/i)
  assert.throws(() => c.confirmRemoteOffset(s.sessionId, 42, 10), /offset/i)
  assert.throws(() => c.confirmRemoteOffset(s.sessionId, 42, s.encryptedSize + 1), /offset/i)
  assert.equal(c.confirmRemoteOffset(s.sessionId, 42, s.encryptedSize), s.encryptedSize)
  assert.equal(c.status(s.sessionId, 42).remoteCommittedBytes, s.encryptedSize)
})

test("cannot complete without both all chunks and full remote ciphertext", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage()), s = makeSession(MiB + 3)
  c.start(s)
  assert.throws(() => c.complete(s.sessionId, 42), /cannot be finalized/i)
  for (let i = 0; i < s.chunkCount; i++) {
    const d = hash(String(i)); c.reserveChunk(s.sessionId, 42, i, d)
    c.acknowledgeChunk(s.sessionId, 42, i, d)
  }
  assert.throws(() => c.complete(s.sessionId, 42), /cannot be finalized/i)
  c.confirmRemoteOffset(s.sessionId, 42, s.encryptedSize)
  assert.equal(c.complete(s.sessionId, 42).phase, "completed")
  assert.equal(c.complete(s.sessionId, 42).phase, "completed")
  assert.throws(() => c.reserveChunk(s.sessionId, 42, 0, hash("0")), /not receiving/i)
})

test("aborted session can never re-encrypt or restart with the same header", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage()), s = makeSession()
  c.start(s)
  assert.equal(c.abort(s.sessionId, 42).phase, "aborted")
  assert.equal(c.abort(s.sessionId, 42).phase, "aborted")
  assert.equal(c.start(s).phase, "aborted")
  assert.throws(() => c.reserveChunk(s.sessionId, 42, 0, hash("abc")), /not receiving/i)
  assert.throws(() => c.complete(s.sessionId, 42), /cannot be finalized/i)
})

test("completed session cannot be aborted", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage()), s = makeSession(0)
  c.start(s)
  c.reserveChunk(s.sessionId, 42, 0, hash(""))
  c.acknowledgeChunk(s.sessionId, 42, 0, hash(""))
  c.confirmRemoteOffset(s.sessionId, 42, s.encryptedSize)
  c.complete(s.sessionId, 42)
  assert.throws(() => c.abort(s.sessionId, 42), /cannot be aborted/i)
})

test("20 GiB session initial state uses constant-sized storage", () => {
  const c = new DurableV2UploadCoordinator(new TestSqliteDurableStorage())
  const s = makeSession(20 * 1024 ** 3)
  assert.equal(s.chunkCount, 20480)
  assert.equal(c.start(s).acknowledgedChunks, 0)
})

test("unrelated coordinator instances share persisted receipts but not memory", () => {
  const db = new TestSqliteDurableStorage(), s = makeSession()
  const a = new DurableV2UploadCoordinator(db), b = new DurableV2UploadCoordinator(db)
  a.start(s)
  a.reserveChunk(s.sessionId, 42, 0, hash("same"))
  b.acknowledgeChunk(s.sessionId, 42, 0, hash("same"))
  assert.equal(a.status(s.sessionId, 42).acknowledgedChunks, 1)
})
