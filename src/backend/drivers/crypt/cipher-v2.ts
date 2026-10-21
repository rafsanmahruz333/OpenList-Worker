
import { scryptSync } from "node:crypto"

// Experimental Crypt V2. Not connected to the existing driver.
// Layout:
// [48-byte header][encrypted chunks with 16-byte GCM tags]
//
// Header:
//  0-7:   Magic "RFOSENC2"
//  8-23:  Random per-file salt
// 24-31:  Random nonce prefix
// 32-35:  Chunk size (uint32 big-endian)
// 36-43:  Original size (uint64 big-endian)
// 44-47:  Reserved zero bytes

const MAGIC = new TextEncoder().encode("RFOSENC2")
const HEADER_SIZE = 48
const CHUNK_SIZE = 1024 * 1024
const TAG_SIZE = 16

// Small-file prototype. Streaming support comes later.
const MAX_TEST_BYTES = 8 * CHUNK_SIZE

function chunkCount(size: number): number {
  return Math.max(1, Math.ceil(size / CHUNK_SIZE))
}

function nonceFor(
  header: Uint8Array,
  index: number,
): Uint8Array {
  const nonce = new Uint8Array(12)
  nonce.set(header.subarray(24, 32), 0)
  new DataView(nonce.buffer).setUint32(8, index, false)
  return nonce
}

async function deriveKey(
  password: string,
  vaultSalt: string,
  fileSalt: Uint8Array,
): Promise<CryptoKey> {
  if (!password) {
    throw new Error("Crypt V2 password cannot be empty")
  }

  const salt = Buffer.concat([
    Buffer.from("RFOSENC2\0"),
    Buffer.from(vaultSalt, "utf8"),
    Buffer.from([0]),
    Buffer.from(fileSalt),
  ])

  const keyBytes = scryptSync(password, salt, 32, {
    N: 16384,
    r: 8,
    p: 1,
  })

  return crypto.subtle.importKey(
    "raw",
    new Uint8Array(keyBytes),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  )
}

function inspectHeader(data: Uint8Array): {
  header: Uint8Array
  size: number
  chunks: number
} {
  if (data.length < HEADER_SIZE + TAG_SIZE) {
    throw new Error("Crypt V2 file is too short")
  }

  const header = data.subarray(0, HEADER_SIZE)

  if (!MAGIC.every((byte, i) => header[i] === byte)) {
    throw new Error("Not a Crypt V2 file")
  }

  const view = new DataView(
    header.buffer,
    header.byteOffset,
    header.byteLength,
  )

  if (view.getUint32(32, false) !== CHUNK_SIZE) {
    throw new Error("Unsupported chunk size")
  }

  if (header.subarray(44, 48).some((byte) => byte !== 0)) {
    throw new Error("Unsupported header flags")
  }

  const bigSize = view.getBigUint64(36, false)

  if (bigSize > BigInt(MAX_TEST_BYTES)) {
    throw new Error("Prototype limit: 8 MiB")
  }

  const size = Number(bigSize)
  const chunks = chunkCount(size)

  const expectedSize =
    HEADER_SIZE + size + chunks * TAG_SIZE

  if (data.length !== expectedSize) {
    throw new Error("Encrypted file is truncated or malformed")
  }

  return { header, size, chunks }
}

export async function encryptV2(
  plain: Uint8Array,
  password: string,
  vaultSalt = "",
): Promise<Uint8Array> {
  if (plain.length > MAX_TEST_BYTES) {
    throw new Error("Prototype limit: 8 MiB")
  }

  const header = new Uint8Array(HEADER_SIZE)
  header.set(MAGIC, 0)

  crypto.getRandomValues(header.subarray(8, 32))

  const view = new DataView(header.buffer)
  view.setUint32(32, CHUNK_SIZE, false)
  view.setBigUint64(36, BigInt(plain.length), false)

  const key = await deriveKey(
    password,
    vaultSalt,
    header.subarray(8, 24),
  )

  const chunks = chunkCount(plain.length)
  const output = new Uint8Array(
    HEADER_SIZE + plain.length + chunks * TAG_SIZE,
  )

  output.set(header)

  let position = HEADER_SIZE

  for (let i = 0; i < chunks; i++) {
    const part = plain.subarray(
      i * CHUNK_SIZE,
      Math.min(plain.length, (i + 1) * CHUNK_SIZE),
    )

    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: nonceFor(header, i) as BufferSource,
          additionalData: header,
          tagLength: 128,
        },
        key,
        part as BufferSource,
      ),
    )

    output.set(encrypted, position)
    position += encrypted.length
  }

  return output
}

export async function decryptV2(
  data: Uint8Array,
  password: string,
  vaultSalt = "",
): Promise<Uint8Array> {
  const { header, size, chunks } = inspectHeader(data)

  const key = await deriveKey(
    password,
    vaultSalt,
    header.subarray(8, 24),
  )

  const output = new Uint8Array(size)
  let position = HEADER_SIZE

  for (let i = 0; i < chunks; i++) {
    const partSize = Math.min(
      CHUNK_SIZE,
      size - i * CHUNK_SIZE,
    )

    const encrypted = data.subarray(
      position,
      position + partSize + TAG_SIZE,
    )

    try {
      const plainPart = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: "AES-GCM",
            iv: nonceFor(header, i) as BufferSource,
            additionalData: header as BufferSource,
            tagLength: 128,
          },
          key,
          encrypted as BufferSource,
        ),
      )

      output.set(plainPart, i * CHUNK_SIZE)
    } catch {
      throw new Error(
        "Authentication failed: wrong password, salt, or damaged data",
      )
    }

    position += partSize + TAG_SIZE
  }

  return output
}
