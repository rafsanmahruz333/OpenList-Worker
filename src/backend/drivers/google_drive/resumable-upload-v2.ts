/**
 * Google Drive v3 resumable-upload transport for RFOSENC2 ciphertext.
 *
 * Independent of encryption, storage mounts, user authentication, and DO coordination.
 * No file content or session URL is persisted here. The caller MUST keep the
 * Google session URL private and reconcile the durable coordinator's offset
 * against Google's authoritative status before retrying an uncertain PUT.
 *
 * Never log sessionUrl: its upload_id acts as a capability credential.
 */

export const DRIVE_UPLOAD_ALIGNMENT = 256 * 1024
export const DRIVE_UPLOAD_MAX_WINDOW = 16 * 1024 * 1024
const INIT_URL = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true"

export type DriveUploadProgress =
  | { state: "incomplete"; nextOffset: number }
  | { state: "complete"; nextOffset: number; fileId: string }

export type DriveFetch = typeof fetch

function validTotal(totalBytes: number): void {
  if (!Number.isSafeInteger(totalBytes) || totalBytes <= 0) {
    throw new Error("[CryptV2 Drive] Invalid ciphertext length")
  }
}

/** Only permit the Google Drive upload endpoint; never follow redirects. */
export function assertGoogleDriveUploadSessionUrl(sessionUrl: string): void {
  let url: URL
  try { url = new URL(sessionUrl) }
  catch { throw new Error("[CryptV2 Drive] Invalid Google upload session URL") }
  if (url.protocol !== "https:" || url.hostname !== "www.googleapis.com" ||
      url.port !== "" || url.username || url.password ||
      url.pathname !== "/upload/drive/v3/files" ||
      url.searchParams.get("uploadType") !== "resumable" ||
      !url.searchParams.get("upload_id") || url.hash) {
    throw new Error("[CryptV2 Drive] Untrusted Google upload session URL")
  }
}

function parseProgress(response: Response, totalBytes: number): DriveUploadProgress {
  if (response.status === 308) {
    const raw = response.headers.get("Range")
    if (!raw) return { state: "incomplete", nextOffset: 0 }
    const match = /^bytes=0-(\d+)$/.exec(raw)
    if (!match) throw new Error("[CryptV2 Drive] Invalid Google upload Range")
    const last = Number(match[1])
    const nextOffset = last + 1
    if (!Number.isSafeInteger(last) || nextOffset >= totalBytes ||
        nextOffset % DRIVE_UPLOAD_ALIGNMENT !== 0) {
      // A non-aligned partial checkpoint cannot be advanced by the DO yet.
      throw new Error("[CryptV2 Drive] Unusable Google upload checkpoint")
    }
    return { state: "incomplete", nextOffset }
  }
  if (response.status === 200 || response.status === 201) {
    // A status query can yield completion even after a client disconnect.
    // Google Drive should return file metadata on completion.
    return { state: "complete", nextOffset: totalBytes, fileId: "" }
  }
  if (response.status === 404 || response.status === 410) {
    throw new Error("[CryptV2 Drive] Upload session expired; start a new session and RFOSENC2 header")
  }
  // Do not expose response bodies: they may include private request metadata.
  throw new Error(`[CryptV2 Drive] Unexpected Google upload status ${response.status}; query session state before retrying`)
}

async function parseCompletion(response: Response, totalBytes: number): Promise<DriveUploadProgress> {
  const progress = parseProgress(response, totalBytes)
  if (progress.state === "incomplete") return progress
  let metadata: unknown
  try { metadata = await response.json() }
  catch { throw new Error("[CryptV2 Drive] Google upload completed without file metadata") }
  if (!metadata || typeof metadata !== "object" ||
      typeof (metadata as { id?: unknown }).id !== "string" ||
      !(metadata as { id: string }).id.trim()) {
    throw new Error("[CryptV2 Drive] Google upload completed without a file ID")
  }
  return { state: "complete", nextOffset: totalBytes, fileId: (metadata as { id: string }).id }
}

function validateUploadRequest(totalBytes: number, offset: number, body: Uint8Array): void {
  validTotal(totalBytes)
  if (!(body instanceof Uint8Array) || !body.byteLength ||
      body.byteLength > DRIVE_UPLOAD_MAX_WINDOW) {
    throw new Error("[CryptV2 Drive] Invalid upload window bytes")
  }
  if (!Number.isSafeInteger(offset) || offset < 0 ||
      offset % DRIVE_UPLOAD_ALIGNMENT !== 0 ||
      offset >= totalBytes || body.byteLength > totalBytes - offset) {
    throw new Error("[CryptV2 Drive] Invalid upload offset or length")
  }
  const isFinal = offset + body.byteLength === totalBytes
  if (!isFinal && body.byteLength % DRIVE_UPLOAD_ALIGNMENT !== 0) {
    throw new Error("[CryptV2 Drive] Non-final Google upload body must be 256 KiB aligned")
  }
}

export class GoogleDriveResumableV2 {
  constructor(private readonly request: DriveFetch = fetch) {}

  /** Initiate a new session; caller must privately and durably safeguard the returned URL. */
  async initiate(input: {
    parentId: string
    filename: string
    ciphertextBytes: number
    accessToken: string
  }): Promise<string> {
    const { parentId, filename, ciphertextBytes, accessToken } = input
    validTotal(ciphertextBytes)
    if (!parentId?.trim() || !filename?.trim() ||
        filename.includes("/") || filename.includes("\\") ||
        !filename.endsWith(".rfv2") || !accessToken?.trim()) {
      throw new Error("[CryptV2 Drive] Invalid upload initiation metadata")
    }
    const response = await this.request(INIT_URL, {
      method: "POST",
      redirect: "manual",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json; charset=UTF-8",
        "X-Upload-Content-Type": "application/octet-stream",
        "X-Upload-Content-Length": String(ciphertextBytes),
      },
      body: JSON.stringify({ name: filename, parents: [parentId], mimeType: "application/octet-stream" }),
    })
    if (response.status !== 200) {
      throw new Error(`[CryptV2 Drive] Upload initialization failed: HTTP ${response.status}`)
    }
    const sessionUrl = response.headers.get("Location") || ""
    assertGoogleDriveUploadSessionUrl(sessionUrl)
    return sessionUrl
  }

  /** Query Google's authoritative committed offset after any uncertain network result. */
  async query(sessionUrl: string, totalBytes: number): Promise<DriveUploadProgress> {
    validTotal(totalBytes)
    assertGoogleDriveUploadSessionUrl(sessionUrl)
    const response = await this.request(sessionUrl, {
      method: "PUT",
      redirect: "manual",
      headers: { "Content-Range": `bytes */${totalBytes}`, "Content-Length": "0" },
    })
    return parseCompletion(response, totalBytes)
  }

  /** PUT a bounded ciphertext window; trust the returned Range, not the sent length. */
  async putWindow(
    sessionUrl: string, totalBytes: number, offset: number, bytes: Uint8Array,
  ): Promise<DriveUploadProgress> {
    assertGoogleDriveUploadSessionUrl(sessionUrl)
    validateUploadRequest(totalBytes, offset, bytes)
    const end = offset + bytes.byteLength - 1
    const response = await this.request(sessionUrl, {
      method: "PUT",
      redirect: "manual",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(bytes.byteLength),
        "Content-Range": `bytes ${offset}-${end}/${totalBytes}`,
      },
      body: bytes as BodyInit,
    })
    const progress = await parseCompletion(response, totalBytes)
    if (progress.state === "complete" && end + 1 !== totalBytes) {
      throw new Error("[CryptV2 Drive] Google completed before expected final ciphertext window")
    }
    if (progress.state === "incomplete" &&
        (progress.nextOffset < offset || progress.nextOffset > end + 1)) {
      throw new Error("[CryptV2 Drive] Google acknowledged bytes outside submitted window")
    }
    return progress
  }
}
