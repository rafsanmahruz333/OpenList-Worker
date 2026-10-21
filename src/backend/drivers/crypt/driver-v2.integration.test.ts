import test from "node:test"
import assert from "node:assert/strict"
import { CryptV2Driver } from "./driver-v2"

// Safe integration test: fake Google Drive, fake download URL, demo credentials.
// Does not access Cloudflare, real Google Drive, or any existing vault.
test("CryptV2 driver: mocked Google Drive round-trip", async (t) => {
  const storage = new Map<string, Buffer>()
  const root = "/encrypted"
  const filename = "recovery-check.txt"
  const physical = `${root}/${filename}.rfv2`
  const original = Buffer.from("CryptV2 driver integration: private content")

  function fileItem(name: string, size: number, isDir = false) {
    return {
      name,
      size,
      is_dir: isDir,
      modified: new Date(0).toISOString(),
      sign: "",
      type: isDir ? 1 : 0,
      raw_url: isDir ? "" : "https://example.invalid/mock-drive-file",
      raw_url_headers: isDir ? undefined : { Authorization: "Bearer fake-test-token" },
    }
  }

  const mockGoogleDrive = {
    async put(_virtual: string, path: string, content: Buffer) {
      storage.set(path, Buffer.from(content))
    },
    async list(_virtual: string, path: string) {
      assert.equal(path, root)
      return [...storage.entries()].map(([key, value]) =>
        fileItem(key.split("/").pop() || "", value.length),
      )
    },
    async get(_virtual: string, path: string) {
      if (path === root) return fileItem("encrypted", 0, true)
      const content = storage.get(path)
      if (!content) throw new Error("Mock Google Drive: file not found")
      return fileItem(path.split("/").pop() || "", content.length)
    },
  }

  const driver = new CryptV2Driver({
    remote_path: "/Drive-Test/Secure-V2-Test",
    password: "demonstration-password-12345",
    salt: "demonstration-salt-12345",
  })

  // Inject fake storage to avoid connecting to the real database or cloud.
  Object.assign(driver, { remoteDriver: mockGoogleDrive, remoteRoot: root })

  const seenRanges: string[] = []
  const realFetch = globalThis.fetch
  globalThis.fetch = async (_input, init) => {
    const header = new Headers(init?.headers)
    assert.equal(header.get("authorization"), "Bearer fake-test-token")
    const bytes = storage.get(physical)
    if (!bytes) return new Response(null, { status: 404 })
    const requested = header.get("Range")
    if (requested) {
      seenRanges.push(requested)
      const parsed = /^bytes=(\d+)-(\d+)$/.exec(requested)
      assert.ok(parsed, "expected an inclusive HTTP byte range")
      const start = Number(parsed[1])
      const end = Number(parsed[2])
      assert.ok(start >= 0 && end >= start && end < bytes.length)
      return new Response(new Uint8Array(bytes.subarray(start, end + 1)) as BodyInit, {
        status: 206,
        headers: {
          "Content-Range": `bytes ${start}-${end}/${bytes.length}`,
          "Content-Length": String(end - start + 1),
        },
      })
    }
    return new Response(new Uint8Array(bytes) as BodyInit, {
      status: 200,
      headers: { "Content-Length": String(bytes.length) },
    })
  }

  try {
    await t.test("upload writes encrypted bytes only", async () => {
      await driver.put("/Secure-Test/recovery-check.txt", `/${filename}`, original)
      const encrypted = storage.get(physical)
      assert.ok(encrypted, "expected a .rfv2 file")
      assert.equal(encrypted.subarray(0, 8).toString(), "RFOSENC2")
      assert.notDeepEqual(encrypted.subarray(48, 48 + original.length), original)
    })

    await t.test("listing and file metadata hide the .rfv2 suffix", async () => {
      const entries = await driver.list("/Secure-Test", "/")
      assert.equal(entries.length, 1)
      assert.equal(entries[0].name, filename)
      assert.equal(entries[0].size, original.length)
      assert.equal(entries[0].raw_url, "")
      const info = await driver.get(`/Secure-Test/${filename}`, `/${filename}`)
      assert.equal(info.name, filename)
      assert.equal(info.size, original.length)
      assert.equal(info.raw_url, "")
    })

    await t.test("download decrypts and forwards the auth header", async () => {
      const stream = await driver.createReadStream(`/${filename}`)
      const recovered = Buffer.from(await new Response(stream as BodyInit).arrayBuffer())
      assert.deepEqual(recovered, original)
    })

    await t.test("byte-range download returns the correct segment", async () => {
      const before = seenRanges.length
      const stream = await driver.createReadStream(`/${filename}`, {
        start: 5,
        end: 15,
      })
      const recovered = Buffer.from(await new Response(stream as BodyInit).arrayBuffer())
      assert.deepEqual(recovered, original.subarray(5, 16))
      assert.deepEqual(seenRanges.slice(before), ["bytes=0-47", `bytes=48-${48 + original.length + 15}`])
    })

    await t.test("cross-chunk HTTP ranges authenticate only touched chunks", async () => {
      const old = storage.get(physical)!
      const multi = Buffer.alloc(1024 * 1024 + 32, 0x63)
      for (let i = 0; i < multi.length; i += 43) multi[i] = i % 251
      try {
        await driver.put(`/Secure-Test/${filename}`, `/${filename}`, multi)
        const start = 1024 * 1024 - 5
        const end = 1024 * 1024 + 9
        const before = seenRanges.length
        const stream = await driver.createReadStream(`/${filename}`, { start, end })
        const received = Buffer.from(await new Response(stream as BodyInit).arrayBuffer())
        assert.deepEqual(received, multi.subarray(start, end + 1))
        assert.equal(seenRanges.length - before, 3, "header plus two chunks")
      } finally {
        storage.set(physical, old)
      }
    })

    await t.test("server ignoring HTTP Range is rejected", async () => {
      const originalFetch = globalThis.fetch
      globalThis.fetch = async (_input, init) => {
        const headers = new Headers(init?.headers)
        assert.ok(headers.has("Range"), "must request partial file")
        return new Response(new Uint8Array(storage.get(physical)!) as BodyInit, { status: 200 })
      }
      try {
        await assert.rejects(
          () => driver.createReadStream(`/${filename}`, { start: 0, end: 5 }),
          /HTTP 206/,
        )
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    await t.test("incorrect Content-Range is rejected", async () => {
      const originalFetch = globalThis.fetch
      globalThis.fetch = async (_input, init) => {
        const headers = new Headers(init?.headers)
        assert.equal(headers.get("Range"), "bytes=0-47")
        return new Response(new Uint8Array(storage.get(physical)!.subarray(0, 48)) as BodyInit, {
          status: 206,
          headers: { "Content-Range": "bytes 1-48/9999", "Content-Length": "48" },
        })
      }
      try {
        await assert.rejects(
          () => driver.createReadStream(`/${filename}`, { start: 0, end: 5 }),
          /incorrect Content-Range/,
        )
      } finally {
        globalThis.fetch = originalFetch
      }
    })

    await t.test("tampered ranged ciphertext fails authentication", async () => {
      const old = storage.get(physical)!
      const corrupted = Buffer.from(old)
      corrupted[60] ^= 1
      storage.set(physical, corrupted)
      try {
        await assert.rejects(
          () => driver.createReadStream(`/${filename}`, { start: 0, end: 10 }),
          /authentication failed/i,
        )
      } finally {
        storage.set(physical, old)
      }
    })

    await t.test("modified cloud ciphertext is rejected", async () => {
      const encrypted = storage.get(physical)!
      const damaged = Buffer.from(encrypted)
      damaged[49] ^= 1
      storage.set(physical, damaged)
      await assert.rejects(async () => {
        const stream = await driver.createReadStream(`/${filename}`)
        await new Response(stream as BodyInit).arrayBuffer()
      }, /authentication failed/i)
      storage.set(physical, encrypted)
    })

    await t.test("oversize upload is rejected before reaching Google Drive", async () => {
      await assert.rejects(
        () => driver.put("/Secure-Test/large.bin", "/large.bin", Buffer.alloc(8 * 1024 * 1024 + 1)),
        /8 MiB/i,
      )
      assert.equal(storage.has(`${root}/large.bin.rfv2`), false)
    })
  } finally {
    globalThis.fetch = realFetch
  }
})
