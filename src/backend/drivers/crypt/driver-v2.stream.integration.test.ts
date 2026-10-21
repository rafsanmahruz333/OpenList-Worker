import test from "node:test"
import assert from "node:assert/strict"
import { createCipheriv, randomBytes, scryptSync } from "node:crypto"
import { CryptV2Driver } from "./driver-v2"

// Fully offline driver integration: fake Google Drive, fake HTTP responses,
// independent native AES-256-GCM writer and disposable test credentials.
const MIB = 1024 * 1024
const PASSWORD = "demonstration-stream-driver-password"
const SALT = "demonstration-stream-driver-vault-salt"
const ROOT = "/encrypted"
const FILE = "stream-large.bin"

function fixture(plain: Buffer): Buffer {
  const header = Buffer.alloc(48)
  header.write("RFOSENC2")
  randomBytes(24).copy(header, 8)
  header.writeUInt32BE(MIB, 32)
  header.writeBigUInt64BE(BigInt(plain.length), 36)
  const key = scryptSync(PASSWORD, Buffer.concat([
    Buffer.from("RFOSENC2\0"), Buffer.from(SALT), Buffer.from([0]),
    header.subarray(8, 24),
  ]), 32, { N: 16384, r: 8, p: 1 })
  const output: Buffer[] = [header]
  for (let i = 0; i < Math.max(1, Math.ceil(plain.length / MIB)); i++) {
    const nonce = Buffer.alloc(12)
    header.copy(nonce, 0, 24, 32)
    nonce.writeUInt32BE(i, 8)
    const cipher = createCipheriv("aes-256-gcm", key, nonce)
    cipher.setAAD(header)
    output.push(cipher.update(plain.subarray(i * MIB, (i + 1) * MIB)))
    output.push(cipher.final(), cipher.getAuthTag())
  }
  return Buffer.concat(output)
}

function item(name: string, size: number) {
  return {
    name,
    size,
    is_dir: false,
    modified: new Date(0).toISOString(),
    sign: "",
    type: 0,
    raw_url: "https://example.invalid/cryptv2-driver-stream-test",
    raw_url_headers: { Authorization: "Bearer fake-test-token" },
  }
}

test("CryptV2 driver: read-only 11 MiB authenticated streaming", async (t) => {
  const plain = randomBytes(11 * MIB + 2345)
  const encrypted = fixture(plain)
  const getRequests: string[] = []
  const driver = new CryptV2Driver({
    remote_path: "/Drive-V2-Test/Encrypted-V2",
    password: PASSWORD,
    salt: SALT,
  })
  const googleMock = {
    async get(_virtual: string, path: string) {
      assert.equal(path, `${ROOT}/${FILE}.rfv2`)
      return item(`${FILE}.rfv2`, encrypted.length)
    },
    async list(_virtual: string, path: string) {
      assert.equal(path, ROOT)
      return [item(`${FILE}.rfv2`, encrypted.length)]
    },
    async put() { throw new Error("Unimplemented: no actual upload permitted") },
  }
  Object.assign(driver, { remoteDriver: googleMock, remoteRoot: ROOT })

  const oldFetch = globalThis.fetch
  globalThis.fetch = async (_url, init) => {
    assert.equal(init?.redirect, "manual", "never follow a cross-origin redirect with a Google token")
    const headers = new Headers(init?.headers)
    assert.equal(headers.get("Authorization"), "Bearer fake-test-token")
    assert.equal(headers.get("Accept-Encoding"), "identity")
    const range = headers.get("Range")
    assert.ok(range, "Full encrypted-file HTTP GET must not occur")
    getRequests.push(range)
    const match = /^bytes=(\d+)-(\d+)$/.exec(range)
    assert.ok(match, `Unexpected Range header: ${range}`)
    const start = Number(match[1])
    const end = Number(match[2])
    assert.ok(start >= 0 && end >= start && end < encrypted.length)
    return new Response(new Uint8Array(encrypted.subarray(start, end + 1)) as BodyInit, {
      status: 206,
      headers: {
        "Content-Range": `bytes ${start}-${end}/${encrypted.length}`,
        "Content-Length": String(end - start + 1),
      },
    })
  }
  try {
    await t.test("metadata decodes 11 MiB+ while upload stays at 8 MiB", async () => {
      const listed = await driver.list("/Secure-Test", "/")
      assert.equal(listed[0].name, FILE)
      assert.equal(listed[0].size, plain.length)
      const got = await driver.get(`/Secure-Test/${FILE}`, `/${FILE}`)
      assert.equal(got.size, plain.length)
      assert.equal(got.raw_url, "")
      await assert.rejects(
        () => driver.put("/Secure-Test/too-big.bin", "/too-big.bin", Buffer.alloc(8 * MIB + 1)),
        /8 MiB/i,
      )
    })

    await t.test("full 11 MiB+ download streams exact plaintext in bounded HTTP ranges", async () => {
      const firstRequest = getRequests.length
      const stream = await driver.createReadStream(`/${FILE}`)
      assert.deepEqual(getRequests.slice(firstRequest), ["bytes=0-47"],
        "before consuming, only header should be fetched")
      const recovered = Buffer.from(await new Response(stream as BodyInit).arrayBuffer())
      assert.deepEqual(recovered, plain)
      const used = getRequests.slice(firstRequest)
      assert.ok(used.length > 12)
      assert.ok(used.every((range) => {
        const m = /^bytes=(\d+)-(\d+)$/.exec(range)!
        return Number(m[2]) - Number(m[1]) + 1 <= MIB + 16
      }), "upstream HTTP requests must be at most one encrypted chunk each")
    })

    await t.test("5 MiB+ requested range streams across several windows", async () => {
      const start = 3 * MIB - 13
      const end = 9 * MIB + 17
      const stream = await driver.createReadStream(`/${FILE}`, { start, end })
      const recovered = Buffer.from(await new Response(stream as BodyInit).arrayBuffer())
      assert.deepEqual(recovered, plain.subarray(start, end + 1))
    })

    await t.test("near-end seeking avoids fetching earlier data chunks", async () => {
      const firstRequest = getRequests.length
      const start = plain.length - 100
      const stream = await driver.createReadStream(`/${FILE}`, { start, end: plain.length - 1 })
      const recovered = Buffer.from(await new Response(stream as BodyInit).arrayBuffer())
      assert.deepEqual(recovered, plain.subarray(start))
      const requests = getRequests.slice(firstRequest)
      assert.equal(requests.length, 2, "header plus final authenticated chunk")
      assert.equal(requests[0], "bytes=0-47")
      assert.match(requests[1], /^bytes=115345/) // last chunk begins after 11 full MiB chunks
    })
  } finally {
    globalThis.fetch = oldFetch
  }
})
