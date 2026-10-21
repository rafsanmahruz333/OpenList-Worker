/**
 * Experimental, authenticated CryptV2 large-file reader.
 * Compatible with existing RFOSENC2/.rfv2 files; does not change encryption
 * format, upload behavior, storage drivers, or existing credentials.
 *
 * Uses the already-tested <=4 MiB decryptV2RemoteRange primitive to serve
 * sequential chunks with Web Streams backpressure. Individual chunks are
 * authenticated before delivery; a later corrupted chunk can fail AFTER
 * earlier chunks were already delivered (normal authenticated streaming).
 *
 * A future optimization should cache the parsed header and derived key across
 * chunks rather than deriving the key again for each read window.
 */
import {
  decryptV2RemoteRange,
  inspectV2Remote,
  type CryptV2RangeReader,
  type CryptV2Metadata,
} from "./cipher-v2-range"

const MIB = 1024 * 1024
const MAX_WINDOW = 4 * MIB
const DEFAULT_WINDOW = 3 * MIB

export interface V2StreamOptions {
  /** Inclusive plaintext byte position, default 0. */
  start?: number
  /** Inclusive plaintext end position, default file size - 1. */
  end?: number
  /** Number of plaintext bytes to yield per pull (1 .. 4 MiB). */
  windowBytes?: number
  /** Known encrypted file size from cloud metadata, strongly recommended. */
  expectedEncryptedSize?: number
}

export interface V2StreamResult {
  metadata: CryptV2Metadata
  /** Inclusive verified-at-read-time plaintext interval. */
  start: number
  end: number
  stream: ReadableStream<Uint8Array>
}

export async function createV2RemoteStream(
  read: CryptV2RangeReader,
  password: string,
  vaultSalt: string,
  options: V2StreamOptions = {},
): Promise<V2StreamResult> {
  if (!password) throw new Error("[CryptV2] Encryption password required")

  const windowBytes = options.windowBytes ?? DEFAULT_WINDOW
  if (!Number.isSafeInteger(windowBytes) || windowBytes < 1 || windowBytes > MAX_WINDOW) {
    throw new Error("[CryptV2] Invalid streaming read window")
  }

  // Header is untrusted until AES-GCM successfully authenticates a chunk.
  const metadata = await inspectV2Remote(read, options.expectedEncryptedSize)
  if (metadata.plainSize === 0) {
    // The existing full-file decoder verifies the GCM tag of the empty chunk.
    throw new Error("[CryptV2] Empty file requires authenticated full-file decoder")
  }

  const start = options.start ?? 0
  const end = options.end ?? metadata.plainSize - 1
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) ||
      start < 0 || end < start || end >= metadata.plainSize) {
    throw new Error("[CryptV2] Invalid plaintext stream range")
  }

  let offset = start
  let canceled = false
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (canceled) return
      if (offset > end) {
        controller.close()
        return
      }
      const pieceEnd = Math.min(end, offset + windowBytes - 1)
      try {
        const plaintext = await decryptV2RemoteRange(
          read, password, vaultSalt, offset, pieceEnd, metadata.encryptedSize,
        )
        if (canceled) return
        controller.enqueue(plaintext)
        offset = pieceEnd + 1
        if (offset > end) controller.close()
      } catch (error) {
        if (!canceled) controller.error(error)
      }
    },
    cancel() { canceled = true },
  }, { highWaterMark: 0 }) // Fetch a window only as downstream requests data.

  return { metadata, start, end, stream }
}
