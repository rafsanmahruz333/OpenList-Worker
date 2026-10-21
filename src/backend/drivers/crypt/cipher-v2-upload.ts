/**
 * CryptV2 incremental upload encryption prototype.
 *
 * Creates RFOSENC2-compatible header and authenticates individual 1 MiB chunks.
 * Contains no Cloudflare, Google Drive or session-persistence logic.
 * This module does NOT lift the existing 8 MiB upload limit.
 *
 * CRITICAL INTEGRATION INVARIANT: For a given file header and chunk index,
 * NEVER encrypt two different plaintexts. An AES-GCM nonce must never be reused
 * with distinct plaintext. A real resumable-upload driver must persist an
 * immutable per-chunk digest/receipt and reject conflicting retries across
 * Worker restarts/instances, not just within a single in-memory encryptor.
 */
import { scryptSync } from "node:crypto"

const MAGIC = new TextEncoder().encode("RFOSENC2")
const HEADER_SIZE = 48
const CHUNK_SIZE = 1024 * 1024
const TAG_SIZE = 16
const MAX_CHUNKS = 0x1_0000_0000

export interface V2UploadMetadata {
  plainSize: number
  encryptedSize: number
  chunkSize: number
  chunkCount: number
}

export interface V2UploadEncryptor {
  /** Persist this header durably before accepting file content. */
  header: Uint8Array
  metadata: V2UploadMetadata
  /** Exactly one complete plaintext chunk; only the last may be shorter. */
  encryptChunk(index: number, plaintext: Uint8Array): Promise<Uint8Array>
}

function metadataFromSize(size: number): V2UploadMetadata {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error("[CryptV2] Invalid source file size")
  }
  const chunkCount = Math.max(1, Math.ceil(size / CHUNK_SIZE))
  if (chunkCount > MAX_CHUNKS) {
    throw new Error("[CryptV2] File exceeds format chunk counter")
  }
  const encryptedSize = HEADER_SIZE + size + chunkCount * TAG_SIZE
  if (!Number.isSafeInteger(encryptedSize)) {
    throw new Error("[CryptV2] Encrypted size is not safely representable")
  }
  return { plainSize: size, encryptedSize, chunkSize: CHUNK_SIZE, chunkCount }
}

export function newV2UploadHeader(plainSize: number): Uint8Array {
  metadataFromSize(plainSize)
  const header = new Uint8Array(HEADER_SIZE)
  header.set(MAGIC)
  crypto.getRandomValues(header.subarray(8, 32))
  const view = new DataView(header.buffer)
  view.setUint32(32, CHUNK_SIZE, false)
  view.setBigUint64(36, BigInt(plainSize), false)
  return header
}

function inspectHeader(source: Uint8Array): { header: Uint8Array; metadata: V2UploadMetadata } {
  if (!(source instanceof Uint8Array) || source.byteLength !== HEADER_SIZE) {
    throw new Error("[CryptV2] Upload header must be exactly 48 bytes")
  }
  // Copy so caller changes cannot silently rotate AES-GCM associated data.
  const header = new Uint8Array(source)
  if (!MAGIC.every((v, i) => header[i] === v)) {
    throw new Error("[CryptV2] Invalid RFOSENC2 header magic")
  }
  const view = new DataView(header.buffer)
  if (view.getUint32(32, false) !== CHUNK_SIZE ||
      header.subarray(44, 48).some(x => x !== 0)) {
    throw new Error("[CryptV2] Unsupported upload header")
  }
  const value = view.getBigUint64(36, false)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("[CryptV2] Unsafe plaintext size")
  }
  return { header, metadata: metadataFromSize(Number(value)) }
}

function nonceFor(header: Uint8Array, index: number): Uint8Array {
  const nonce = new Uint8Array(12)
  nonce.set(header.subarray(24, 32))
  new DataView(nonce.buffer).setUint32(8, index, false)
  return nonce
}

/**
 * Reconstruct encryptor from persisted header, e.g. in a new upload request.
 * The caller MUST enforce one immutable plaintext per (header, chunk index)
 * across invocations, before calling encryptChunk.
 */
export async function openV2UploadEncryptor(
  inputHeader: Uint8Array,
  password: string,
  vaultSalt: string,
): Promise<V2UploadEncryptor> {
  if (!password || !vaultSalt) {
    throw new Error("[CryptV2] Password and vault salt are required")
  }
  const { header, metadata } = inspectHeader(inputHeader)
  const salt = Buffer.concat([
    Buffer.from("RFOSENC2\0"),
    Buffer.from(vaultSalt, "utf8"),
    Buffer.from([0]),
    Buffer.from(header.subarray(8, 24)),
  ])
  const keyBytes = scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 })
  const key = await crypto.subtle.importKey(
    "raw", new Uint8Array(keyBytes), "AES-GCM", false, ["encrypt"],
  )
  const usedIndices = new Set<number>()

  return {
    header,
    metadata,
    async encryptChunk(index, plaintext) {
      if (!Number.isSafeInteger(index) || index < 0 || index >= metadata.chunkCount) {
        throw new Error("[CryptV2] Invalid upload chunk index")
      }
      if (!(plaintext instanceof Uint8Array)) {
        throw new Error("[CryptV2] Chunk must be bytes")
      }
      const offset = index * CHUNK_SIZE
      const expected = Math.min(CHUNK_SIZE, metadata.plainSize - offset)
      if (plaintext.byteLength !== expected) {
        throw new Error("[CryptV2] Incorrect upload chunk size")
      }
      if (usedIndices.has(index)) {
        throw new Error("[CryptV2] Reusing a GCM nonce is forbidden")
      }
      // Mark before awaiting crypto operation: concurrent attempts must not
      // reuse an IV, even if they supply different plaintext.
      usedIndices.add(index)
      return new Uint8Array(await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonceFor(header, index) as BufferSource,
          additionalData: header as BufferSource,
          tagLength: 128,
        },
        key,
        plaintext as BufferSource,
      ))
    },
  }
}

export async function newV2UploadEncryptor(
  plainSize: number,
  password: string,
  vaultSalt: string,
): Promise<V2UploadEncryptor> {
  return openV2UploadEncryptor(newV2UploadHeader(plainSize), password, vaultSalt)
}
