/** Bounded I/O for a long-lived Agent. No remote command policy lives here. */
export const COMMAND_OUTPUT_LIMIT = 4 * 1024 * 1024;
export const JSON_RESPONSE_LIMIT = 4 * 1024 * 1024;

export async function readCommandOutput(
  stream: ReadableStream<Uint8Array>,
  limit = COMMAND_OUTPUT_LIMIT,
): Promise<string> {
  // Reuse a small BYOB buffer. read-all/default readers allocate large backing
  // stores even for empty subprocess pipes; frequent probes amplify retention.
  const reader = stream.getReader({ mode: "byob" });
  let buffer: ArrayBuffer = new ArrayBuffer(8192);
  const decoder = new TextDecoder();
  const parts: string[] = [];
  let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read(new Uint8Array(buffer));
      if (done) break;
      bytes += value.byteLength;
      if (bytes > limit) throw new Error("Command output exceeded its byte budget.");
      parts.push(decoder.decode(value, { stream: true }));
      buffer = value.buffer;
    }
    parts.push(decoder.decode());
    return parts.join("").trim();
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
}

export async function captureCommand(
  process: Deno.ChildProcess,
  timeoutMs: number,
  kill: () => void,
  limit = COMMAND_OUTPUT_LIMIT,
) {
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    kill();
  }, timeoutMs);
  const stdout = readCommandOutput(process.stdout, limit);
  const stderr = readCommandOutput(process.stderr, limit);
  try {
    const [out, err, status] = await Promise.all([stdout, stderr, process.status]);
    return {
      code: timedOut ? 124 : status.code,
      stdout: out,
      stderr: timedOut ? `Command timed out after ${timeoutMs}ms.` : err,
    };
  } catch (error) {
    kill();
    await Promise.allSettled([stdout, stderr, process.status]);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

export async function withResponse<T>(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  consume: (response: Response) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response | undefined;
  try {
    response = await fetch(url, { ...init, signal: controller.signal });
    return await consume(response);
  } finally {
    controller.abort();
    await response?.body?.cancel().catch(() => undefined);
    clearTimeout(timer);
  }
}

export function byteBudget(limit: number, onBytes?: (bytes: number) => void) {
  let total = 0;
  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      total += chunk.byteLength;
      if (total > limit) throw new Error("Transfer exceeded its byte budget.");
      onBytes?.(total);
      controller.enqueue(chunk);
    },
  });
}

export async function readJson(response: Response): Promise<unknown> {
  if (!response.body) return {};
  const body = response.body.pipeThrough(byteBudget(JSON_RESPONSE_LIMIT));
  // This response is bounded before the JSON decoder can accumulate it.
  const text = await new Response(body).text();
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

/** Signed object uploads need a fixed Content-Length, not chunked encoding.
 * fetch discards a caller-supplied Content-Length for streaming bodies in the
 * supported runtimes. Load this transport only when a file job needs it.
 */
export async function uploadStream(
  url: string,
  file: Deno.FsFile,
  size: number,
  method: string,
  headers: Headers,
  timeoutMs: number,
): Promise<number> {
  const parsed = new URL(url);
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Unsupported upload scheme.");
  const transport = parsed.protocol === "https:"
    ? await import("node:https")
    : await import("node:http");
  headers.set("Content-Length", String(size));
  headers.delete("Transfer-Encoding");
  const request = transport.request(parsed, {
    method,
    headers: Object.fromEntries(headers),
    agent: false,
  });
  const timer = setTimeout(
    () => request.destroy(new Error("Upload deadline exceeded.")),
    timeoutMs,
  );
  const response = new Promise<void>((resolve, reject) => {
    request.once("error", reject);
    request.once("response", (message) => {
      const status = message.statusCode ?? 0;
      message.destroy();
      if (status >= 200 && status < 300) resolve();
      else reject(new Error(`Upload returned HTTP ${status}.`));
    });
  });
  const send = async () => {
    const buffer = new Uint8Array(65536);
    let sent = 0;
    while (sent < size) {
      const count = await file.read(buffer.subarray(0, Math.min(buffer.length, size - sent)));
      if (count === null) throw new Error("Upload file became shorter.");
      await new Promise<void>((resolve, reject) => {
        request.write(buffer.subarray(0, count), (error) => error ? reject(error) : resolve());
      });
      sent += count;
    }
    request.end();
  };
  const sending = send();
  try {
    await Promise.all([sending, response]);
    return size;
  } finally {
    clearTimeout(timer);
    request.destroy(new Error("Upload cancelled."));
    await Promise.allSettled([sending, response]);
  }
}
