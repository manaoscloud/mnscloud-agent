import { assert, assertEquals, assertRejects } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { byteBudget, captureCommand, readJson, uploadStream, withResponse } from "./bounded-io.ts";
import { runLane } from "./scheduler.ts";

function command(code: string, timeout = 5000, limit = 4 * 1024 * 1024) {
  const process = new Deno.Command(Deno.execPath(), {
    args: ["eval", code],
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  return captureCommand(process, timeout, () => {
    try {
      process.kill("SIGKILL");
    } catch { /* Already exited. */ }
  }, limit);
}

Deno.test("capture drains both pipes, preserves UTF-8 and reports nonzero exit", async () => {
  const result = await command(`
    const bytes=new TextEncoder().encode('é'.repeat(100000));
    const writeAll=async(w)=>{let offset=0;while(offset<bytes.length) offset+=await w.write(bytes.subarray(offset));};
    await Promise.all([writeAll(Deno.stdout),writeAll(Deno.stderr)]);
    Deno.exit(3);`);
  assertEquals(result.code, 3);
  assertEquals(result.stdout, "é".repeat(100000));
  assertEquals(result.stderr, result.stdout);
});

Deno.test("capture rejects oversized output and reaps the process", async () => {
  await assertRejects(
    () =>
      command(
        `
    while(true) await Deno.stdout.write(new Uint8Array(8192));`,
        5000,
        16384,
      ),
    Error,
    "byte budget",
  );
});

Deno.test("capture times out a silent process", async () => {
  const result = await command("setInterval(()=>{},1000);await new Promise(()=>{});", 200);
  assertEquals(result.code, 124);
});

Deno.test("HTTP deadline covers a stalled response body and cancels it", async () => {
  const original = globalThis.fetch;
  let cancelled = false;
  globalThis.fetch = (_input, init) =>
    Promise.resolve(
      new Response(
        new ReadableStream({
          start(controller) {
            init?.signal?.addEventListener("abort", () => {
              cancelled = true;
              controller.error(new DOMException("Aborted", "AbortError"));
            }, { once: true });
          },
        }),
      ),
    );
  try {
    await assertRejects(() => withResponse("https://example.invalid", {}, 30, readJson));
    assert(cancelled);
  } finally {
    globalThis.fetch = original;
  }
});

Deno.test("JSON responses are bounded before decoding", async () => {
  const response = new Response(
    new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(65536));
      },
    }),
  );
  await assertRejects(() => readJson(response), Error, "byte budget");
});

Deno.test("streamed files close cleanly and byte budgets reject excess data", async () => {
  const dir = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(`${dir}/source`, "hello");
    {
      using source = await Deno.open(`${dir}/source`);
      using target = await Deno.open(`${dir}/target`, { create: true, write: true });
      await source.readable.pipeThrough(byteBudget(5)).pipeTo(target.writable);
    }
    assertEquals(await Deno.readTextFile(`${dir}/target`), "hello");
    using source = await Deno.open(`${dir}/source`);
    await assertRejects(
      () => new Response(source.readable.pipeThrough(byteBudget(4))).text(),
      Error,
      "byte budget",
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("HTTP upload streams a file with its declared content length", async () => {
  const path = await Deno.makeTempFile();
  const content = new Uint8Array(65537).fill(42);
  await Deno.writeFile(path, content);
  let received: unknown;
  const server = Deno.serve({ hostname: "127.0.0.1", port: 0, onListen() {} }, async (request) => {
    const bytes = new Uint8Array(await request.arrayBuffer());
    received = {
      length: request.headers.get("content-length"),
      size: bytes.length,
      intact: bytes.every((byte) => byte === 42),
    };
    return new Response(null, { status: 200 });
  });
  try {
    using file = await Deno.open(path);
    const size = await uploadStream(
      `http://127.0.0.1:${server.addr.port}/upload`,
      file,
      content.length,
      "PUT",
      new Headers(),
      5000,
    );
    assertEquals(size, content.length);
    assertEquals(received, { length: String(content.length), size: content.length, intact: true });
  } finally {
    await server.shutdown();
    await Deno.remove(path);
  }
});

Deno.test("a blocked job lane does not block heartbeat or overlap jobs", async () => {
  const stop = new AbortController();
  let release!: () => void;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  let jobs = 0;
  let beats = 0;
  const job = runLane(
    async () => {
      jobs++;
      await blocked;
    },
    1,
    () => {},
    stop.signal,
  );
  const heartbeat = runLane(
    () => {
      beats++;
      if (beats === 3) {
        stop.abort();
        release();
      }
      return Promise.resolve();
    },
    1,
    () => {},
    stop.signal,
  );
  await Promise.all([job, heartbeat]);
  assertEquals(jobs, 1);
  assertEquals(beats, 3);
});

Deno.test("upload failure closes transport even when the source becomes shorter", async () => {
  const path = await Deno.makeTempFile();
  await Deno.writeTextFile(path, "short");
  const server = Deno.serve(
    { hostname: "127.0.0.1", port: 0, onListen() {} },
    () => new Response(null, { status: 503 }),
  );
  try {
    using file = await Deno.open(path);
    await assertRejects(() =>
      uploadStream(
        `http://127.0.0.1:${server.addr.port}/`,
        file,
        1000000,
        "PUT",
        new Headers(),
        1000,
      )
    );
  } finally {
    await server.shutdown();
    await Deno.remove(path);
  }
});
