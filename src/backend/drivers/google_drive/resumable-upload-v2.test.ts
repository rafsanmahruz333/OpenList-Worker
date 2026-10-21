import test from "node:test"
import assert from "node:assert/strict"
import {
  GoogleDriveResumableV2,
  assertGoogleDriveUploadSessionUrl,
  DRIVE_UPLOAD_ALIGNMENT as A,
} from "./resumable-upload-v2"

const url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=test-123"
const mockFetch = (handler: (url: string, init: RequestInit) => Response) =>
  (async (input: string | URL | Request, init?: RequestInit): Promise<Response> =>
    handler(String(input), init || {})) as typeof fetch

function response(status: number, headers?: Record<string,string>, body?: object) {
  return new Response(body ? JSON.stringify(body) : null, {status, headers})
}

test("initializes encrypted file using Google Drive with bearer token only on initiation", async () => {
  let seen = false
  const client = new GoogleDriveResumableV2(mockFetch((input, init) => {
    assert.match(input, /^https:\/\/www\.googleapis\.com\/upload\/drive\/v3\/files/)
    assert.equal(init.method, "POST")
    assert.equal(init.redirect, "manual")
    assert.equal(new Headers(init.headers).get("Authorization"), "Bearer private-token")
    assert.equal(new Headers(init.headers).get("X-Upload-Content-Length"), String(20 * A))
    assert.deepEqual(JSON.parse(String(init.body)), { name:"movie.mp4.rfv2", parents:["folder-id"], mimeType:"application/octet-stream" })
    seen = true
    return response(200, { Location: url })
  }))
  assert.equal(await client.initiate({parentId:"folder-id",filename:"movie.mp4.rfv2",ciphertextBytes:20*A,accessToken:"private-token"}),url)
  assert.equal(seen, true)
})

test("rejects session URI redirects or host spoofing", () => {
  for (const s of ["http://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=x", "https://evil.example/upload/drive/v3/files?uploadType=resumable&upload_id=x", "https://www.googleapis.com.evil.example/upload/drive/v3/files?uploadType=resumable&upload_id=x", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable", "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=x#frag"]) {
    assert.throws(()=>assertGoogleDriveUploadSessionUrl(s))
  }
})

test("refuses unexpected initiation redirect without following it", async () => {
  const client = new GoogleDriveResumableV2(mockFetch((_url, init) => {
    assert.equal(init.redirect,"manual")
    return response(302, { Location:"https://bad.example/" })
  }))
  await assert.rejects(()=>client.initiate({parentId:"abc",filename:"f.rfv2",ciphertextBytes:50,accessToken:"secret"}),/initialization failed/i)
})

test("rejects untrusted Location header even after HTTP 200", async () => {
  const client = new GoogleDriveResumableV2(mockFetch(()=>response(200,{Location:"https://bad.example/"})))
  await assert.rejects(()=>client.initiate({parentId:"abc",filename:"f.rfv2",ciphertextBytes:50,accessToken:"secret"}),/untrusted/i)
})

test("status of new session has 308 without Range and starts at zero", async () => {
  const client = new GoogleDriveResumableV2(mockFetch((s, init)=>{
    assert.equal(s,url)
    assert.equal(new Headers(init.headers).get("Content-Range"),`bytes */${3*A+9}`)
    assert.equal(new Headers(init.headers).get("Authorization"),null)
    return response(308)
  }))
  assert.deepEqual(await client.query(url,3*A+9),{state:"incomplete",nextOffset:0})
})

test("query parses inclusive Range as next byte offset", async () => {
  const client = new GoogleDriveResumableV2(mockFetch(()=>response(308,{Range:`bytes=0-${2*A-1}`})))
  assert.deepEqual(await client.query(url,5*A),{state:"incomplete",nextOffset:2*A})
})

test("query fails closed on malformed and unaligned Range", async () => {
  for (const h of ["bytes=4-262143", "bytes=0-nope", "bytes=0-8", `bytes=0-${4*A-1}`]) {
    const client = new GoogleDriveResumableV2(mockFetch(()=>response(308,{Range:h})))
    await assert.rejects(()=>client.query(url,4*A))
  }
})

test("writes bounded aligned ciphertext with exact Content-Range", async () => {
  const bytes = new Uint8Array(A)
  const client = new GoogleDriveResumableV2(mockFetch((_s, init)=>{
    assert.equal(init.redirect,"manual")
    assert.equal(init.method,"PUT")
    assert.equal(new Headers(init.headers).get("Content-Length"),String(A))
    assert.equal(new Headers(init.headers).get("Content-Range"),`bytes ${A}-${2*A-1}/${4*A+5}`)
    assert.equal(new Headers(init.headers).get("Authorization"),null)
    assert.equal(init.body,bytes)
    return response(308,{Range:`bytes=0-${2*A-1}`})
  }))
  assert.deepEqual(await client.putWindow(url,4*A+5,A,bytes),{state:"incomplete",nextOffset:2*A})
})

test("partial acknowledgement never assumes entire PUT committed", async () => {
  const client = new GoogleDriveResumableV2(mockFetch(()=>response(308,{Range:`bytes=0-${A-1}`})))
  assert.deepEqual(await client.putWindow(url,5*A,0,new Uint8Array(2*A)),{state:"incomplete",nextOffset:A})
})

test("short unaligned last window completes only with file ID", async () => {
  const client = new GoogleDriveResumableV2(mockFetch(()=>response(200,{"Content-Type":"application/json"},{id:"google-id"})))
  assert.deepEqual(await client.putWindow(url,2*A+77,2*A,new Uint8Array(77)),{state:"complete",nextOffset:2*A+77,fileId:"google-id"})
})

test("rejects oversized, misaligned, zero-length, and out-of-range PUTs", async () => {
  const client = new GoogleDriveResumableV2(mockFetch(()=>{throw Error("should not fetch")}))
  for (const [total,offset,bytes] of ([[3*A,0,new Uint8Array(A-1)], [3*A,1,new Uint8Array(A)], [3*A,0,new Uint8Array()], [3*A,3*A,new Uint8Array(A)], [30*A,0,new Uint8Array(17*1024*1024)]] as Array<[number, number, Uint8Array]>)) {
    await assert.rejects(()=>client.putWindow(url,total,offset,bytes))
  }
})

test("fails closed if Google acknowledges backwards or beyond supplied window", async () => {
  for (const end of [A-1,4*A-1]) {
    const client = new GoogleDriveResumableV2(mockFetch(()=>response(308,{Range:`bytes=0-${end}`})))
    await assert.rejects(()=>client.putWindow(url,5*A,2*A,new Uint8Array(A)),/outside submitted window/i)
  }
})

test("expired Google upload sessions require a new encrypted header", async () => {
  for (const code of [404,410]) {
    const client = new GoogleDriveResumableV2(mockFetch(()=>response(code)))
    await assert.rejects(()=>client.query(url,5*A),/expired/i)
  }
})

test("completed status query verifies returned Google file ID", async () => {
  const client = new GoogleDriveResumableV2(mockFetch(()=>response(201,{"Content-Type":"application/json"},{id:"file123"})))
  assert.deepEqual(await client.query(url,5*A),{state:"complete",nextOffset:5*A,fileId:"file123"})
})

test("an ambiguous server failure is not treated as successful progress", async () => {
  const client = new GoogleDriveResumableV2(mockFetch(()=>response(503)))
  await assert.rejects(()=>client.putWindow(url,2*A,0,new Uint8Array(A)),/query session state/i)
})
