
import {
  StorageDriver,
  FileItem,
  calcFileType,
} from "../../internal/driver/base"
import { encryptV2, decryptV2 } from "./cipher-v2"
import { decryptV2RemoteRange } from "./cipher-v2-range"
import { createV2RemoteStream } from "./cipher-v2-stream"

export interface CryptV2Addition {
  remote_path: string
  password: string
  salt: string
}

const SUFFIX = ".rfv2"
const CHUNK = 1024 * 1024
const HEADER = 48
const TAG = 16
const MAX_PLAIN = 8 * CHUNK // upload and legacy full-file decoding limit
const MAX_READ_PLAIN = 64 * CHUNK // initial read-only streaming test ceiling
const MAX_READ_ENCRYPTED = HEADER + MAX_READ_PLAIN + 64 * TAG
const MAX_ENCRYPTED = HEADER + MAX_PLAIN + 8 * TAG

function decodedSize(bytes: number): number {
  if (
    !Number.isSafeInteger(bytes) ||
    bytes < HEADER + TAG ||
    bytes > MAX_READ_ENCRYPTED
  ) {
    return -1
  }

  for (let blocks = 1; blocks <= 64; blocks++) {
    const plain = bytes - HEADER - blocks * TAG

    if (
      plain >= 0 &&
      plain <= MAX_READ_PLAIN &&
      Math.max(1, Math.ceil(plain / CHUNK)) === blocks
    ) {
      return plain
    }
  }

  return -1
}

export class CryptV2Driver implements StorageDriver {
  private remoteDriver: StorageDriver | null = null
  private remoteRoot = "/"

  constructor(private addition: CryptV2Addition) {}

  async init(): Promise<void> {
    if (
      !this.addition.password ||
      this.addition.password.length < 16
    ) {
      throw new Error(
        "[CryptV2] Use a dedicated password of at least 16 characters",
      )
    }

    if (
      !this.addition.salt ||
      this.addition.salt.length < 16
    ) {
      throw new Error(
        "[CryptV2] Supply a separate salt of at least 16 characters",
      )
    }

    const { resolvePath } = await import(
      "../../internal/model/db"
    )
    const { getDriver } = await import(
      "../../internal/op/storage"
    )

    const resolved = await resolvePath(
      this.addition.remote_path || "/",
    )

    if (resolved.isVirtual || !resolved.storage) {
      throw new Error(
        "[CryptV2] Remote path must point to an existing storage",
      )
    }

    const underlying = resolved.storage.driver
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "")

    if (underlying !== "googledrive") {
      throw new Error(
        "[CryptV2] Prototype supports GoogleDrive only",
      )
    }

    this.remoteRoot = resolved.physical || "/"
    this.remoteDriver = await getDriver(
      resolved.storage.driver,
      resolved.storage,
    )
  }

  private remote(path: string): string {
    const p = path.startsWith("/") ? path : "/" + path
    const root = this.remoteRoot === "/"
      ? ""
      : this.remoteRoot.replace(/\/$/, "")

    return (root + p).replace(/\/{2,}/g, "/").replace(/\/+$/, "") || "/"
  }

  private backend(): StorageDriver {
    if (!this.remoteDriver) {
      throw new Error("[CryptV2] Storage not initialized")
    }
    return this.remoteDriver
  }

  async list(
    _virtualPath: string,
    physicalPath: string,
  ): Promise<FileItem[]> {
    const files = await this.backend().list(
      "",
      this.remote(physicalPath),
    )

    return files.flatMap((item): FileItem[] => {
      if (item.is_dir) return [item]

      if (!item.name.endsWith(SUFFIX)) return []

      const name = item.name.slice(0, -SUFFIX.length)
      const size = decodedSize(item.size)

      return [{
        ...item,
        name,
        size: Math.max(0, size),
        type: calcFileType(name, false),
        thumb: "",
        raw_url: "",
        raw_url_headers: undefined,
      }]
    })
  }

  async get(
    _virtualPath: string,
    physicalPath: string,
  ): Promise<FileItem> {
    const remotePath = this.remote(physicalPath)
    const backend = this.backend()

    try {
      const item = await backend.get(
        "",
        remotePath + SUFFIX,
      )

      if (!item.is_dir && item.raw_url) {
        const size = decodedSize(item.size)

        if (size < 0) {
          throw new Error(
            "[CryptV2] Invalid encrypted file size",
          )
        }

        const name = item.name.slice(0, -SUFFIX.length)

        return {
          ...item,
          name,
          size,
          type: calcFileType(name, false),
          thumb: "",
          raw_url: "",
          raw_url_headers: undefined,
        }
      }
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.includes("Invalid encrypted file size")
      ) {
        throw error
      }
    }

    const directory = await backend.get("", remotePath)

    if (directory.is_dir) return directory

    throw new Error("[CryptV2] Encrypted file not found")
  }

  async put(
    _virtualPath: string,
    physicalPath: string,
    content: Buffer,
  ): Promise<void> {
    if (content.length > MAX_PLAIN) {
      throw new Error("[CryptV2] Prototype limit: 8 MiB")
    }

    const encrypted = await encryptV2(
      new Uint8Array(content),
      this.addition.password,
      this.addition.salt,
    )

    await this.backend().put(
      "",
      this.remote(physicalPath) + SUFFIX,
      Buffer.from(encrypted),
    )
  }

  async createReadStream(
    physicalPath: string,
    range?: { start: number; end: number },
  ): Promise<ReadableStream<Uint8Array>> {
    const item = await this.backend().get(
      "",
      this.remote(physicalPath) + SUFFIX,
    )

    if (
      item.is_dir ||
      !item.raw_url ||
      decodedSize(item.size) < 0
    ) {
      throw new Error(
        "[CryptV2] File missing or exceeds the 64 MiB read limit",
      )
    }

    // Stream all nonempty files using authenticated Google Drive byte ranges.
    // Preserve the existing authenticated full-file decoder for empty files.
    if (decodedSize(item.size) > 0) {
      const downloadUrl = item.raw_url
      const readEncryptedRange = async (start: number, end: number): Promise<Uint8Array> => {
        const headers = new Headers(item.raw_url_headers ?? {})
        headers.set("Range", `bytes=${start}-${end}`)
        headers.set("Accept-Encoding", "identity")

        // Do not forward a Google access token to a redirected host.
        const partial = await fetch(downloadUrl, { headers, redirect: "manual" })
        if (partial.status !== 206) {
          throw new Error(`[CryptV2] Google Drive did not return HTTP 206 (got ${partial.status})`)
        }
        const expectedRange = `bytes ${start}-${end}/${item.size}`
        if (partial.headers.get("Content-Range") !== expectedRange) {
          throw new Error("[CryptV2] Google Drive returned an incorrect Content-Range")
        }
        const encoding = partial.headers.get("Content-Encoding")
        if (encoding && encoding.toLowerCase() !== "identity") {
          throw new Error("[CryptV2] Compressed HTTP range response is not supported")
        }
        const expectedLength = end - start + 1
        const lengthHeader = partial.headers.get("Content-Length")
        if (lengthHeader !== null && Number(lengthHeader) !== expectedLength) {
          throw new Error("[CryptV2] Incorrect encrypted range Content-Length")
        }
        const data = new Uint8Array(await partial.arrayBuffer())
        if (data.byteLength !== expectedLength) {
          throw new Error("[CryptV2] Incorrect encrypted range body length")
        }
        return data
      }

      // Keep the already live-verified short-range behavior unchanged.
      if (range && range.end - range.start + 1 <= 4 * CHUNK) {
        const plainRange = await decryptV2RemoteRange(
          readEncryptedRange,
          this.addition.password,
          this.addition.salt,
          range.start,
          range.end,
          item.size,
        )
        return new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(plainRange)
            controller.close()
          },
        })
      }

      // Large requested ranges and full-file downloads are authenticated
      // sequentially, without buffering the entire encrypted file.
      const result = await createV2RemoteStream(
        readEncryptedRange,
        this.addition.password,
        this.addition.salt,
        {
          ...(range ? { start: range.start, end: range.end } : {}),
          expectedEncryptedSize: item.size,
          windowBytes: 2 * CHUNK,
        },
      )
      return result.stream
    }

    const response = await fetch(item.raw_url, {
      headers: item.raw_url_headers ?? {},
    })

    if (!response.ok) {
      throw new Error(
        `[CryptV2] Google Drive download failed: ${response.status}`,
      )
    }

    const contentLength = Number(
      response.headers.get("Content-Length"),
    )

    if (
      Number.isFinite(contentLength) &&
      contentLength > MAX_ENCRYPTED
    ) {
      throw new Error("[CryptV2] Download exceeds size limit")
    }

    const encrypted = new Uint8Array(
      await response.arrayBuffer(),
    )

    if (encrypted.length > MAX_ENCRYPTED) {
      throw new Error("[CryptV2] Download exceeds size limit")
    }

    const plain = await decryptV2(
      encrypted,
      this.addition.password,
      this.addition.salt,
    )

    const result = range
      ? plain.slice(range.start, range.end + 1)
      : plain

    return new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(result)
        controller.close()
      },
    })
  }

  async mkdir(): Promise<void> {
    throw new Error("[CryptV2] Creating folders is not yet supported")
  }

  async rename(): Promise<void> {
    throw new Error("[CryptV2] Rename is not yet supported")
  }

  async remove(): Promise<void> {
    throw new Error("[CryptV2] Delete is not yet supported")
  }

  async move(): Promise<void> {
    throw new Error("[CryptV2] Move is not yet supported")
  }

  async copy(): Promise<void> {
    throw new Error("[CryptV2] Copy is not yet supported")
  }
}
