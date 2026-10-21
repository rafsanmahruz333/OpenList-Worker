/**
 * CryptV2 random-access read prototype. Does NOT change existing CryptV2 uploads.
 * Works with the existing RFOSENC2 / .rfv2 file format.
 *
 * The provider MUST return exactly the requested inclusive encrypted byte range.
 * It must reject an upstream server that ignores HTTP Range (status 200) rather
 * than downloading entire files. HTTP validation belongs to the provider.
 *
 * Only the requested plaintext interval is returned. All overlapping 1 MiB
 * encrypted chunks are authenticated with AES-256-GCM before any bytes return.
 * Header metadata is NOT authenticated until a chunk is successfully decrypted.
 */
import { scryptSync } from "node:crypto"

const HEADER_SIZE = 48
const CHUNK_SIZE = 1024 * 1024
const TAG_SIZE = 16
const MAX_RANGE = 4 * CHUNK_SIZE
const MAX_CHUNKS = 0x1_0000_0000 // 32-bit chunk index in AES-GCM nonce
const MAGIC = new TextEncoder().encode("RFOSENC2")

/** Inclusive encrypted byte range: start and end both count. */
export type CryptV2RangeReader = (
  start: number,
  end: number,
) => Promise<Uint8Array>

export interface CryptV2Metadata {
  /** Original unencrypted content length, in bytes. */
  plainSize: number
  /** Expected size of the complete encrypted file, in bytes. */
  encryptedSize: number
  /** Fixed, existing CryptV2 format chunk size. */
  chunkSize: number
  /** Number of authenticated chunks, including one empty chunk for empty files. */
  chunkCount: number
}

interface ParsedHeader extends CryptV2Metadata {
  bytes: Uint8Array
}

async function readExactly(
  read: CryptV2RangeReader,
  start: number,
  end: number,
): Promise<Uint8Array> {
  const data = await read(start, end)
  if (!(data instanceof Uint8Array) || data.byteLength !== end - start + 1) {
    throw new Error("[CryptV2] Remote server returned the wrong byte range")
  }
  return data
}

async function readHeader(
  read: CryptV2RangeReader,
  expectedEncryptedSize?: number,
): Promise<ParsedHeader> {
  const bytes = await readExactly(read, 0, HEADER_SIZE - 1)
  if (!MAGIC.every((byte, i) => bytes[i] === byte)) {
    throw new Error("[CryptV2] Not an RFOSENC2 encrypted file")
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (view.getUint32(32, false) !== CHUNK_SIZE) {
    throw new Error("[CryptV2] Unsupported encryption chunk size")
  }
  if (bytes.subarray(44, 48).some((byte) => byte !== 0)) {
    throw new Error("[CryptV2] Unsupported header flags")
  }

  const encodedSize = view.getBigUint64(36, false)
  if (encodedSize > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("[CryptV2] File size cannot be safely represented")
  }

  const plainSize = Number(encodedSize)
  const chunkCount = Math.max(1, Math.ceil(plainSize / CHUNK_SIZE))
  if (chunkCount > MAX_CHUNKS) {
    throw new Error("[CryptV2] Too many chunks for nonce counter")
  }
  const encryptedSize = HEADER_SIZE + plainSize + chunkCount * TAG_SIZE
  if (!Number.isSafeInteger(encryptedSize)) {
    throw new Error("[CryptV2] Invalid encrypted file size")
  }
  if (expectedEncryptedSize !== undefined && (
    !Number.isSafeInteger(expectedEncryptedSize) ||
    expectedEncryptedSize !== encryptedSize
  )) {
    throw new Error("[CryptV2] Header disagrees with encrypted file size")
  }

  return { bytes, plainSize, encryptedSize, chunkSize: CHUNK_SIZE, chunkCount }
}

/** Read untrusted size metadata. Authentication happens during decryption. */
export async function inspectV2Remote(
  read: CryptV2RangeReader,
  expectedEncryptedSize?: number,
): Promise<CryptV2Metadata> {
  const { bytes: _bytes, ...metadata } = await readHeader(read, expectedEncryptedSize)
  return metadata
}

function nonceFor(header: Uint8Array, index: number): Uint8Array {
  const nonce = new Uint8Array(12)
  nonce.set(header.subarray(24, 32), 0)
  new DataView(nonce.buffer).setUint32(8, index, false)
  return nonce
}

/**
 * Decrypt at most 4 MiB of requested plaintext, with inclusive start/end.
 * Each touched encrypted chunk (up to ~1 MiB plus GCM tag) is fetched separately.
 * Does not buffer the entire encrypted file, even if it is much larger.
 *
 * For empty files, the caller should retain the existing full-file handler;
 * this partial-range API accepts only nonempty plaintext ranges.
 */
export async function decryptV2RemoteRange(
  read: CryptV2RangeReader,
  password: string,
  vaultSalt: string,
  start: number,
  end: number,
  expectedEncryptedSize?: number,
): Promise<Uint8Array> {
  if (!password) throw new Error("[CryptV2] Password is required")
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) ||
      start < 0 || end < start || end - start + 1 > MAX_RANGE) {
    throw new Error("[CryptV2] Invalid or oversized plaintext byte range")
  }

  const meta = await readHeader(read, expectedEncryptedSize)
  if (end >= meta.plainSize) {
    throw new Error("[CryptV2] Plaintext range exceeds file length")
  }

  const salt = Buffer.concat([
    Buffer.from("RFOSENC2\0"),
    Buffer.from(vaultSalt, "utf8"),
    Buffer.from([0]),
    Buffer.from(meta.bytes.subarray(8, 24)),
  ])
  const keyBytes = scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 })
  const key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(keyBytes),
    "AES-GCM",
    false,
    ["decrypt"],
  )

  const output = new Uint8Array(end - start + 1)
  const first = Math.floor(start / CHUNK_SIZE)
  const last = Math.floor(end / CHUNK_SIZE)

  for (let i = first; i <= last; i++) {
    const plainChunkStart = i * CHUNK_SIZE
    const plainChunkSize = Math.min(CHUNK_SIZE, meta.plainSize - plainChunkStart)
    const encryptedStart = HEADER_SIZE + i * (CHUNK_SIZE + TAG_SIZE)
    const encryptedEnd = encryptedStart + plainChunkSize + TAG_SIZE - 1
    const ciphertextAndTag = await readExactly(read, encryptedStart, encryptedEnd)

    let decryptedChunk: Uint8Array
    try {
      decryptedChunk = new Uint8Array(await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonceFor(meta.bytes, i) as BufferSource,
          additionalData: meta.bytes as BufferSource,
          tagLength: 128,
        },
        key,
        ciphertextAndTag as BufferSource,
      ))
    } catch {
      throw new Error("[CryptV2] Authentication failed: wrong credentials or modified data")
    }

    const wantedStart = Math.max(start, plainChunkStart)
    const wantedEnd = Math.min(end, plainChunkStart + plainChunkSize - 1)
    output.set(
      decryptedChunk.subarray(wantedStart - plainChunkStart, wantedEnd - plainChunkStart + 1),
      wantedStart - start,
    )
  }

  return output
}
