/**
 * Internal-only RPC boundary for CryptV2 upload Durable Objects.
 *
 * Never expose this API directly to browser traffic. The HTTP layer MUST
 * authenticate the user and derive ownerId from the trusted session, not from
 * a request body or user-supplied header.
 *
 * Each upload gets its own SQLite-backed Durable Object to serialize immutable
 * encryption receipts and remote offsets across Worker isolates/restarts.
 */
import {
  DurableV2UploadCoordinator,
  type AcknowledgeOutcome,
  type DurableUploadSnapshot,
  type ReserveOutcome,
} from "./cryptv2-upload-coordinator"
import type { ImmutableV2Session } from "./cryptv2-upload-plan"

/** Shape of the internal Cloudflare DO RPC stub. */
export interface CryptV2UploadDoStub {
  start(input: ImmutableV2Session): Promise<DurableUploadSnapshot>
  status(sessionId: string, ownerId: number): Promise<DurableUploadSnapshot>
  reserveChunk(sessionId: string, ownerId: number, index: number, digest: string): Promise<ReserveOutcome>
  acknowledgeChunk(sessionId: string, ownerId: number, index: number, digest: string): Promise<AcknowledgeOutcome>
  confirmRemoteOffset(sessionId: string, ownerId: number, confirmed: number): Promise<number>
  complete(sessionId: string, ownerId: number): Promise<DurableUploadSnapshot>
  abort(sessionId: string, ownerId: number): Promise<DurableUploadSnapshot>
}

interface DoNamespaceLike {
  idFromName(name: string): unknown
  get(id: unknown): CryptV2UploadDoStub
}

/** Use only the dedicated CRYPTV2_UPLOAD_DO binding, never the database DO. */
export function getCryptV2UploadDoStub(
  env: { CRYPTV2_UPLOAD_DO?: DoNamespaceLike } | undefined,
  sessionId: string,
): CryptV2UploadDoStub {
  if (!/^[a-zA-Z0-9_-]{12,128}$/.test(sessionId)) {
    throw new Error("[CryptV2] Invalid upload session identifier")
  }
  const binding = env?.CRYPTV2_UPLOAD_DO
  if (!binding || typeof binding.idFromName !== "function" || typeof binding.get !== "function") {
    throw new Error("[CryptV2] Dedicated upload Durable Object binding is not configured")
  }
  // Stable routing is essential: all retries and devices for an upload must
  // reach the same transactional coordinator, not arbitrary Worker instances.
  return binding.get(binding.idFromName(`cryptv2-upload:${sessionId}`))
}

/**
 * Thin façade usable both by the real DO class and by local persistence tests.
 * All cryptographic/retry invariants remain in DurableV2UploadCoordinator.
 */
export class CryptV2UploadDoService implements CryptV2UploadDoStub {
  constructor(private readonly coordinator: DurableV2UploadCoordinator) {}

  async start(input: ImmutableV2Session): Promise<DurableUploadSnapshot> {
    return this.coordinator.start(input)
  }
  async status(sessionId: string, ownerId: number): Promise<DurableUploadSnapshot> {
    return this.coordinator.status(sessionId, ownerId)
  }
  async reserveChunk(sessionId: string, ownerId: number, index: number, digest: string): Promise<ReserveOutcome> {
    return this.coordinator.reserveChunk(sessionId, ownerId, index, digest)
  }
  async acknowledgeChunk(sessionId: string, ownerId: number, index: number, digest: string): Promise<AcknowledgeOutcome> {
    return this.coordinator.acknowledgeChunk(sessionId, ownerId, index, digest)
  }
  async confirmRemoteOffset(sessionId: string, ownerId: number, confirmed: number): Promise<number> {
    return this.coordinator.confirmRemoteOffset(sessionId, ownerId, confirmed)
  }
  async complete(sessionId: string, ownerId: number): Promise<DurableUploadSnapshot> {
    return this.coordinator.complete(sessionId, ownerId)
  }
  async abort(sessionId: string, ownerId: number): Promise<DurableUploadSnapshot> {
    return this.coordinator.abort(sessionId, ownerId)
  }
}
