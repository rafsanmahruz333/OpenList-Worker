/**
 * Private SQLite-backed Durable Object coordinating ONE encrypted upload.
 *
 * The Worker must export this class and bind it separately as
 * CRYPTV2_UPLOAD_DO before deployment. No public fetch() route is provided.
 * All calls are internal Cloudflare RPC. Browser authentication, user ownership
 * and path ACL must be enforced BEFORE invoking the RPC stub.
 */
// @ts-ignore Cloudflare provides this runtime module; this repo has not generated Worker types yet.
import { DurableObject } from "cloudflare:workers"
import { DurableV2UploadCoordinator } from "../internal/upload/cryptv2-upload-coordinator"
import { CryptV2UploadDoService } from "../internal/upload/cryptv2-upload-do"
import type { ImmutableV2Session } from "../internal/upload/cryptv2-upload-plan"

export class CryptV2UploadCoordinatorDO extends DurableObject {
  private readonly service: CryptV2UploadDoService

  constructor(ctx: any, env: any) {
    super(ctx, env)
    const storage = ctx?.storage
    if (!storage?.kv || typeof storage.transactionSync !== "function") {
      throw new Error("[CryptV2] SQLite-backed Durable Object storage is required")
    }
    this.service = new CryptV2UploadDoService(new DurableV2UploadCoordinator(storage))
  }

  // RPC only; HTTP routes and Google Drive adapter are intentionally not connected yet.
  async start(input: ImmutableV2Session) { return this.service.start(input) }
  async status(sessionId: string, ownerId: number) { return this.service.status(sessionId, ownerId) }
  async reserveChunk(sessionId: string, ownerId: number, index: number, digest: string) {
    return this.service.reserveChunk(sessionId, ownerId, index, digest)
  }
  async acknowledgeChunk(sessionId: string, ownerId: number, index: number, digest: string) {
    return this.service.acknowledgeChunk(sessionId, ownerId, index, digest)
  }
  async confirmRemoteOffset(sessionId: string, ownerId: number, offset: number) {
    return this.service.confirmRemoteOffset(sessionId, ownerId, offset)
  }
  async complete(sessionId: string, ownerId: number) { return this.service.complete(sessionId, ownerId) }
  async abort(sessionId: string, ownerId: number) { return this.service.abort(sessionId, ownerId) }
}
