/**
 * CryptV2 persistent upload coordinator primitives (NOT publicly exposed).
 *
 * Designed for the strongly consistent, SQLite-backed Durable Object KV store:
 *   new DurableV2UploadCoordinator(ctx.storage)
 *
 * ctx.storage.transactionSync() plus ctx.storage.kv is required. Never provide a
 * Cloudflare KV namespace or an in-process Map in production; neither gives
 * cross-isolate transaction semantics. Durable Object routing and authenticated
 * server endpoints are separate future integration steps.
 *
 * This module never persists encryption passwords, Google upload URLs,
 * plaintext, ciphertext, or file contents.
 */
import {
  checkImmutableChunkReceipt,
  createImmutableV2Session,
  getV2ChunkLayout,
  type ChunkReceipt,
  type ImmutableV2Session,
} from "./cryptv2-upload-plan"

/** Subset of SQLite-backed Durable Object storage; does not require Worker types. */
export interface DurableV2CoordinatorStorage {
  kv: {
    get<T>(key: string): T | undefined
    put(key: string, value: unknown): void
  }
  transactionSync<T>(callback: () => T): T
}

export type UploadPhase = "receiving" | "completed" | "aborted"

export interface DurableUploadSnapshot {
  immutable: ImmutableV2Session
  phase: UploadPhase
  acknowledgedChunks: number
  remoteCommittedBytes: number
}

export type ReserveOutcome = "reserve-new" | "retry-same" | "already-acknowledged"
export type AcknowledgeOutcome = "acknowledged" | "already-acknowledged"

function keyFor(sessionId: string): string {
  if (!/^[a-zA-Z0-9_-]{12,128}$/.test(sessionId)) {
    throw new Error("[CryptV2] Invalid upload session ID")
  }
  return `cv2:s:${sessionId}`
}

function receiptKey(sessionId: string, index: number): string {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new Error("[CryptV2] Invalid chunk index")
  }
  return `cv2:r:${sessionId}:${index}`
}

/** Revalidate caller input even if it was previously produced by the pure planner. */
function validateImmutable(input: ImmutableV2Session): ImmutableV2Session {
  if (!/^[a-f0-9]{96}$/.test(input.headerHex)) {
    throw new Error("[CryptV2] Invalid durable upload header")
  }
  const verified = createImmutableV2Session({
    sessionId: input.sessionId,
    ownerId: input.ownerId,
    path: input.path,
    header: Uint8Array.from(Buffer.from(input.headerHex, "hex")),
    plainSize: input.plainSize,
    createdAtMs: input.createdAtMs,
  })
  if (verified.encryptedSize !== input.encryptedSize ||
      verified.chunkCount !== input.chunkCount) {
    throw new Error("[CryptV2] Inconsistent immutable upload metadata")
  }
  return verified
}

function sameImmutable(a: ImmutableV2Session, b: ImmutableV2Session): boolean {
  return a.sessionId === b.sessionId && a.ownerId === b.ownerId &&
    a.path === b.path && a.headerHex === b.headerHex &&
    a.plainSize === b.plainSize && a.encryptedSize === b.encryptedSize &&
    a.chunkCount === b.chunkCount && a.createdAtMs === b.createdAtMs
}

export class DurableV2UploadCoordinator {
  constructor(private readonly storage: DurableV2CoordinatorStorage) {}

  /**
   * Idempotent setup. A session ID cannot be reused for another owner, target,
   * file length, salt, nonce prefix, or header—even after completion/abortion.
   */
  start(input: ImmutableV2Session): DurableUploadSnapshot {
    const immutable = validateImmutable(input)
    return this.storage.transactionSync(() => {
      const key = keyFor(immutable.sessionId)
      const old = this.storage.kv.get<DurableUploadSnapshot>(key)
      if (old) {
        if (!sameImmutable(old.immutable, immutable)) {
          throw new Error("[CryptV2] Session ID already bound to different immutable metadata")
        }
        return old
      }
      const created: DurableUploadSnapshot = {
        immutable,
        phase: "receiving",
        acknowledgedChunks: 0,
        remoteCommittedBytes: 0,
      }
      this.storage.kv.put(key, created)
      return created
    })
  }

  status(sessionId: string, ownerId: number): DurableUploadSnapshot {
    return this.storage.transactionSync(() => this.loadOwned(sessionId, ownerId))
  }

  /**
   * MUST be called atomically BEFORE encrypting the identified chunk.
   * The plaintext SHA-256 must be computed on the actual received bytes.
   * Retried encryption must be of those identical bytes, verified by digest.
   */
  reserveChunk(
    sessionId: string,
    ownerId: number,
    index: number,
    plaintextSha256: string,
  ): ReserveOutcome {
    return this.storage.transactionSync(() => {
      const s = this.loadReceiving(sessionId, ownerId)
      getV2ChunkLayout(s.immutable.plainSize, index)
      const key = receiptKey(sessionId, index)
      const existing = this.storage.kv.get<ChunkReceipt>(key)
      const outcome = checkImmutableChunkReceipt(existing, index, plaintextSha256)
      if (outcome === "reserve-new") {
        this.storage.kv.put(key, {
          index, digestSha256: plaintextSha256, status: "reserved",
        } satisfies ChunkReceipt)
      }
      return outcome
    })
  }

  /**
   * Mark a chunk acknowledged ONLY once downstream storage has confirmed its
   * ciphertext durably. This is an internal coordinator signal, not proof of
   * Google Drive persistence by itself. The upload adapter must check the
   * remote server's authoritative committed-byte offset independently.
   */
  acknowledgeChunk(
    sessionId: string,
    ownerId: number,
    index: number,
    plaintextSha256: string,
  ): AcknowledgeOutcome {
    return this.storage.transactionSync(() => {
      const s = this.loadReceiving(sessionId, ownerId)
      getV2ChunkLayout(s.immutable.plainSize, index)
      const key = receiptKey(sessionId, index)
      const existing = this.storage.kv.get<ChunkReceipt>(key)
      if (!existing) throw new Error("[CryptV2] Chunk was not reserved")
      const action = checkImmutableChunkReceipt(existing, index, plaintextSha256)
      if (action === "already-acknowledged") return "already-acknowledged"
      this.storage.kv.put(key, { ...existing, status: "acknowledged" } satisfies ChunkReceipt)
      const updated = { ...s, acknowledgedChunks: s.acknowledgedChunks + 1 }
      this.storage.kv.put(keyFor(sessionId), updated)
      return "acknowledged"
    })
  }

  /**
   * Record a confirmed Google Drive contiguous upload offset. Caller MUST
   * first validate the authoritative 308 Range or successful final response.
   * Only increasing offsets are accepted; intermediate offsets must be
   * aligned to Google's 256 KiB boundary. The final offset may be unaligned.
   * On uncertain network failures, query Google's session status and reconcile.
   */
  confirmRemoteOffset(sessionId: string, ownerId: number, confirmed: number): number {
    return this.storage.transactionSync(() => {
      const s = this.loadReceiving(sessionId, ownerId)
      const max = s.immutable.encryptedSize
      if (!Number.isSafeInteger(confirmed) || confirmed < s.remoteCommittedBytes ||
          confirmed > max || (confirmed !== max && confirmed % (256 * 1024) !== 0)) {
        throw new Error("[CryptV2] Invalid confirmed Google Drive upload offset")
      }
      if (confirmed > s.remoteCommittedBytes) {
        this.storage.kv.put(keyFor(sessionId), { ...s, remoteCommittedBytes: confirmed })
      }
      return confirmed
    })
  }

  /** Must have both all chunk receipts and complete remote ciphertext persisted. */
  complete(sessionId: string, ownerId: number): DurableUploadSnapshot {
    return this.storage.transactionSync(() => {
      const s = this.loadOwned(sessionId, ownerId)
      if (s.phase === "completed") return s
      if (s.phase !== "receiving" ||
          s.acknowledgedChunks !== s.immutable.chunkCount ||
          s.remoteCommittedBytes !== s.immutable.encryptedSize) {
        throw new Error("[CryptV2] Upload cannot be finalized before remote confirmation")
      }
      const updated: DurableUploadSnapshot = { ...s, phase: "completed" }
      this.storage.kv.put(keyFor(sessionId), updated)
      return updated
    })
  }

  /** Abort is irreversible for a given header/session ID. Allocate a new header to retry. */
  abort(sessionId: string, ownerId: number): DurableUploadSnapshot {
    return this.storage.transactionSync(() => {
      const s = this.loadOwned(sessionId, ownerId)
      if (s.phase === "completed") {
        throw new Error("[CryptV2] Completed upload cannot be aborted")
      }
      if (s.phase === "aborted") return s
      const updated: DurableUploadSnapshot = { ...s, phase: "aborted" }
      this.storage.kv.put(keyFor(sessionId), updated)
      return updated
    })
  }

  private loadOwned(sessionId: string, ownerId: number): DurableUploadSnapshot {
    const s = this.storage.kv.get<DurableUploadSnapshot>(keyFor(sessionId))
    // Avoid disclosing whether another owner's session exists.
    if (!s || !Number.isSafeInteger(ownerId) || s.immutable.ownerId !== ownerId) {
      throw new Error("[CryptV2] Upload session not found")
    }
    return s
  }

  private loadReceiving(sessionId: string, ownerId: number): DurableUploadSnapshot {
    const s = this.loadOwned(sessionId, ownerId)
    if (s.phase !== "receiving") {
      throw new Error("[CryptV2] Upload session is not receiving")
    }
    return s
  }
}
