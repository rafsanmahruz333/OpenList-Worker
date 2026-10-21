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

  const realFetch = globalThis.fetch
  globalThis.fetch = async (_input, init) => {
    const header = new Headers(init?.headers)
    assert.equal(header.get("authorization"), "Bearer fake-test-token")
    const bytes = storage.get(physical)
    if (!bytes) return new Response(null, { status: 404 })
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
      const stream = await driver.createReadStream(`/${filename}`, {
        start: 5,
        end: 15,
      })
      const recovered = Buffer.from(await new Response(stream as BodyInit).arrayBuffer())
      assert.deepEqual(recovered, original.subarray(5, 16))
    })

    await t.test("modified cloud ciphertext is rejected", async () => {
      const encrypted = storage.get(physical)!
      const damaged = Buffer.from(encrypted)
      damaged[49] ^= 1
      storage.set(physical, damaged)
      await assert.rejects(
        () => driver.createReadStream(`/${filename}`),
        /authentication failed/i,
      )
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
