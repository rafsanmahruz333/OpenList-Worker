/**
 * CryptV2 resumable upload planning and immutable receipt rules.
 * Pure functions: NO Google Drive, Cloudflare, credentials or storage writes.
 *
 * IMPORTANT: These rules do not themselves provide locking/transactions.
 * An SQLite-backed Durable Object must atomically reserve each chunk index
 * before a writer encrypts or uploads the chunk. An upload retry must use
 * the same header, plaintext digest and data. A conflicting digest fails.
 *
 * Google Drive resumable upload PUT bodies must normally be multiples of
 * 256 KiB, except for the final PUT. RFOSENC2 GCM chunk sizes are NOT multiples
 * of 256 KiB, so encrypted bytes have to be packed into aligned PUT bodies.
 */

export const V2_HEADER_BYTES = 48
export const V2_PLAIN_CHUNK_BYTES = 1024 * 1024
export const V2_GCM_TAG_BYTES = 16
export const GDRIVE_ALIGNMENT_BYTES = 256 * 1024
const MAX_NONCE_CHUNKS = 2 ** 32
const MAGIC = new TextEncoder().encode("RFOSENC2")

export interface V2UploadLayout {
  plainSize: number
  encryptedSize: number
  chunkCount: number
}

export interface V2ChunkLayout {
  index: number
  plainStart: number
  plainLength: number
  encryptedStart: number
  encryptedLength: number
}

export interface GooglePutWindow {
  start: number
  end: number // inclusive
  length: number
  isFinal: boolean
}

export interface ImmutableV2Session {
  sessionId: string
  ownerId: number
  path: string
  headerHex: string
  plainSize: number
  encryptedSize: number
  chunkCount: number
  createdAtMs: number
}

export interface ChunkReceipt {
  index: number
  digestSha256: string
  status: "reserved" | "acknowledged"
}

function ensureSafeNonNegativeInteger(value: number, label: string) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`[CryptV2] Invalid ${label}`)
  }
}

export function getV2UploadLayout(plainSize: number): V2UploadLayout {
  ensureSafeNonNegativeInteger(plainSize, "file size")
  const chunkCount = Math.max(1, Math.ceil(plainSize / V2_PLAIN_CHUNK_BYTES))
  if (chunkCount > MAX_NONCE_CHUNKS) {
    throw new Error("[CryptV2] Too many chunks for AES-GCM nonce counter")
  }
  const encryptedSize = V2_HEADER_BYTES + plainSize + chunkCount * V2_GCM_TAG_BYTES
  if (!Number.isSafeInteger(encryptedSize)) {
    throw new Error("[CryptV2] Encrypted size is not safely representable")
  }
  return { plainSize, encryptedSize, chunkCount }
}

export function getV2ChunkLayout(plainSize: number, index: number): V2ChunkLayout {
  const meta = getV2UploadLayout(plainSize)
  if (!Number.isSafeInteger(index) || index < 0 || index >= meta.chunkCount) {
    throw new Error("[CryptV2] Invalid chunk index")
  }
  const plainStart = index * V2_PLAIN_CHUNK_BYTES
  const plainLength = Math.min(V2_PLAIN_CHUNK_BYTES, plainSize - plainStart)
  const encryptedStart = V2_HEADER_BYTES + plainStart + index * V2_GCM_TAG_BYTES
  return {
    index,
    plainStart,
    plainLength,
    encryptedStart,
    encryptedLength: plainLength + V2_GCM_TAG_BYTES,
  }
}

export function createImmutableV2Session(input: {
  sessionId: string
  ownerId: number
  path: string
  header: Uint8Array
  plainSize: number
  createdAtMs: number
}): ImmutableV2Session {
  const { sessionId, ownerId, path, header, plainSize, createdAtMs } = input
  if (!/^[a-zA-Z0-9_-]{12,128}$/.test(sessionId)) {
    throw new Error("[CryptV2] Invalid session identifier")
  }
  if (!Number.isSafeInteger(ownerId) || ownerId < 0) {
    throw new Error("[CryptV2] Invalid session owner")
  }
  if (!path.startsWith("/") || path.includes("\\") || path.includes("\0") ||
      path.split("/").includes("..") || path.length > 2048) {
    throw new Error("[CryptV2] Invalid upload target path")
  }
  ensureSafeNonNegativeInteger(createdAtMs, "creation timestamp")
  const meta = getV2UploadLayout(plainSize)
  if (!(header instanceof Uint8Array) || header.byteLength !== V2_HEADER_BYTES ||
      !MAGIC.every((x, i) => header[i] === x)) {
    throw new Error("[CryptV2] Invalid file header")
  }
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength)
  if (view.getUint32(32, false) !== V2_PLAIN_CHUNK_BYTES ||
      view.getBigUint64(36, false) !== BigInt(plainSize) ||
      header.subarray(44).some(x => x !== 0)) {
    throw new Error("[CryptV2] Header does not match upload layout")
  }
  return {
    sessionId,
    ownerId,
    path,
    headerHex: Buffer.from(header).toString("hex"),
    ...meta,
    createdAtMs,
  }
}

/**
 * Decide whether a retry is safe, given a receipt obtained atomically from
 * a single-writer/transactional coordinator. This is not a concurrency lock.
 */
export function checkImmutableChunkReceipt(
  existing: ChunkReceipt | undefined,
  index: number,
  digestSha256: string,
): "reserve-new" | "retry-same" | "already-acknowledged" {
  if (!Number.isSafeInteger(index) || index < 0) {
    throw new Error("[CryptV2] Invalid chunk index")
  }
  if (!/^[a-f0-9]{64}$/.test(digestSha256)) {
    throw new Error("[CryptV2] Invalid SHA-256 chunk digest")
  }
  if (!existing) return "reserve-new"
  if (existing.index !== index || existing.digestSha256 !== digestSha256) {
    throw new Error("[CryptV2] Conflicting retry: immutable chunk digest mismatch")
  }
  if (existing.status === "acknowledged") return "already-acknowledged"
  if (existing.status === "reserved") return "retry-same"
  throw new Error("[CryptV2] Invalid chunk receipt state")
}

/**
 * Return the next Google Drive PUT window; never buffer the entire upload.
 * A caller supplies encrypted bytes from a separate bounded packetizer.
 */
export function nextGooglePutWindow(
  encryptedSize: number,
  offset: number,
  preferredBytes = 8 * V2_PLAIN_CHUNK_BYTES,
): GooglePutWindow {
  ensureSafeNonNegativeInteger(encryptedSize, "encrypted size")
  ensureSafeNonNegativeInteger(offset, "upload offset")
  if (offset >= encryptedSize || offset % GDRIVE_ALIGNMENT_BYTES !== 0) {
    throw new Error("[CryptV2] Invalid Google upload offset")
  }
  if (!Number.isSafeInteger(preferredBytes) || preferredBytes < GDRIVE_ALIGNMENT_BYTES) {
    throw new Error("[CryptV2] Invalid Google upload window size")
  }
  const available = encryptedSize - offset
  const aligned = Math.floor(preferredBytes / GDRIVE_ALIGNMENT_BYTES) * GDRIVE_ALIGNMENT_BYTES
  const length = Math.min(aligned, available)
  return { start: offset, end: offset + length - 1, length, isFinal: length === available }
}
