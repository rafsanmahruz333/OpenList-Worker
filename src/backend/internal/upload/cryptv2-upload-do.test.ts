import test from "node:test"
import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { newV2UploadHeader } from "../../drivers/crypt/cipher-v2-upload"
import { createImmutableV2Session, getV2UploadLayout } from "./cryptv2-upload-plan"
import { DurableV2UploadCoordinator, type DurableV2CoordinatorStorage } from "./cryptv2-upload-coordinator"
import { CryptV2UploadDoService, getCryptV2UploadDoStub } from "./cryptv2-upload-do"

class FakeSQLite implements DurableV2CoordinatorStorage {
  private db = new Map<string, unknown>()
  kv = {
    get: <T>(key: string): T | undefined => this.db.get(key) as T | undefined,
    put: (key: string, v: unknown) => { this.db.set(key, structuredClone(v)) },
  }
  transactionSync<T>(fn: () => T): T {
    const backup = structuredClone(this.db)
    try { return fn() } catch (e) { this.db = backup; throw e }
  }
}

const fileSize = 2 * 1024 * 1024 + 17
const sha = (x: string) => createHash("sha256").update(x).digest("hex")
const session = (id: string) => createImmutableV2Session({
  sessionId: id, ownerId: 9, path: "/Secure-Test/new-video.mp4",
  header: newV2UploadHeader(fileSize), plainSize: fileSize, createdAtMs: 123456,
})

function setup() {
  const db = new FakeSQLite()
  const rpc = new CryptV2UploadDoService(new DurableV2UploadCoordinator(db))
  const ids: string[] = []
  const env = { CRYPTV2_UPLOAD_DO: {
    idFromName: (name: string) => { ids.push(name); return name },
    get: (_: unknown) => rpc,
  } }
  return { db, rpc, env, ids }
}

test("identical session IDs route to identical Durable Object names", () => {
  const { env, ids } = setup()
  const a = getCryptV2UploadDoStub(env, "session_xyz_1234")
  const b = getCryptV2UploadDoStub(env, "session_xyz_1234")
  assert.equal(a, b)
  assert.deepEqual(ids, ["cryptv2-upload:session_xyz_1234", "cryptv2-upload:session_xyz_1234"])
})

test("different upload sessions have isolated Durable Object routing keys", () => {
  const { env, ids } = setup()
  getCryptV2UploadDoStub(env, "session_xyz_1234")
  getCryptV2UploadDoStub(env, "session_xyz_5678")
  assert.notEqual(ids[0], ids[1])
})

test("missing or incorrect binding fails closed", () => {
  assert.throws(() => getCryptV2UploadDoStub({}, "session_xyz_1234"), /not configured/i)
  assert.throws(() => getCryptV2UploadDoStub({ CRYPTV2_UPLOAD_DO: {} as never }, "session_xyz_1234"), /not configured/i)
})

test("invalid session identifier never calls Durable Object namespace", () => {
  const { env, ids } = setup()
  for (const bad of ["", "short", "../other", "abc:def?ghi", "x".repeat(129)]) {
    assert.throws(() => getCryptV2UploadDoStub(env, bad), /identifier/i)
  }
  assert.equal(ids.length, 0)
})

test("RPC adapter starts session and returns owner-validated status", async () => {
  const { env } = setup()
  const rpc = getCryptV2UploadDoStub(env, "session_xyz_1234")
  const s = session("session_xyz_1234")
  const created = await rpc.start(s)
  assert.equal(created.immutable.encryptedSize, getV2UploadLayout(fileSize).encryptedSize)
  assert.equal((await rpc.status(s.sessionId, 9)).phase, "receiving")
  await assert.rejects(() => rpc.status(s.sessionId, 11), /not found/i)
})

test("RPC adapter preserves conflict rejection across service reconstructions", async () => {
  const { db, rpc } = setup()
  const s = session("session_xyz_1234")
  await rpc.start(s)
  assert.equal(await rpc.reserveChunk(s.sessionId, 9, 0, sha("alpha")), "reserve-new")
  const other = new CryptV2UploadDoService(new DurableV2UploadCoordinator(db))
  assert.equal(await other.reserveChunk(s.sessionId, 9, 0, sha("alpha")), "retry-same")
  await assert.rejects(() => other.reserveChunk(s.sessionId, 9, 0, sha("beta")), /conflicting retry/i)
})

test("RPC adapter tracks acknowledged chunks and rejects premature completion", async () => {
  const { rpc } = setup()
  const s = session("session_xyz_1234")
  await rpc.start(s)
  await rpc.reserveChunk(s.sessionId, 9, 0, sha("chunk"))
  assert.equal(await rpc.acknowledgeChunk(s.sessionId, 9, 0, sha("chunk")), "acknowledged")
  assert.equal((await rpc.status(s.sessionId, 9)).acknowledgedChunks, 1)
  await assert.rejects(() => rpc.complete(s.sessionId, 9), /cannot be finalized/i)
})

test("RPC adapter checks monotonic remote offsets and irreversible abort", async () => {
  const { rpc } = setup()
  const s = session("session_xyz_1234")
  await rpc.start(s)
  assert.equal(await rpc.confirmRemoteOffset(s.sessionId, 9, 256 * 1024), 256 * 1024)
  await assert.rejects(() => rpc.confirmRemoteOffset(s.sessionId, 9, 1), /invalid confirmed/i)
  await rpc.abort(s.sessionId, 9)
  await assert.rejects(() => rpc.reserveChunk(s.sessionId, 9, 0, sha("x")), /not receiving/i)
})
