// PABX registration events: wake signals for the presence report.
//
// The Agent keeps one local connection per engine it manages: Asterisk AMI (`ContactStatus`,
// class `system`) and FreeSWITCH ESL (`sofia::register`, `sofia::unregister`, `sofia::expire`).
// An event only says "something changed"; the Agent then reads the engine and sends the
// difference, so a lost or duplicated event never corrupts the state (the heartbeat stays the
// safety net). Credentials are the local ones the PABX installer writes, read on the host and
// never logged; explicit Agent configuration wins.

export type PresenceEventEngine = "asterisk" | "freeswitch";

export type EventEndpoint = {
  engine: PresenceEventEngine;
  hostname: string;
  port: number;
  /** AMI login name; ESL has none. */
  username?: string;
  secret: string;
};

type Connection = {
  read(buffer: Uint8Array): Promise<number | null>;
  write(data: Uint8Array): Promise<number>;
  close(): void;
};

export type EventListenerOptions = {
  resolve: () => Promise<EventEndpoint | null>;
  onEvent: (engine: PresenceEventEngine) => void;
  log: (level: "info" | "warn", message: string, details?: unknown) => void;
  connect?: (hostname: string, port: number) => Promise<Connection>;
  /** Wait before reconnecting; grows to `maxRetryMs`. */
  retryMs?: number;
  maxRetryMs?: number;
  loginTimeoutMs?: number;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function iniValue(source: string, section: string, key: string) {
  let current = "";
  for (const raw of source.split(/\r?\n/)) {
    const line = raw.replace(/[;#].*$/, "").trim();
    const header = line.match(/^\[([^\]]+)\]/);
    if (header) {
      current = header[1].trim().toLowerCase();
      continue;
    }
    if (current !== section.toLowerCase()) continue;
    const pair = line.match(/^([^=]+?)\s*=>?\s*(.*)$/);
    if (pair && pair[1].trim().toLowerCase() === key.toLowerCase()) return pair[2].trim();
  }
  return "";
}

/** AMI endpoint from `manager.conf` (the account the PABX installer creates for MNSCloud). */
export function amiEndpointFromManagerConf(
  source: string,
  username = "mnscloud",
): EventEndpoint | null {
  const secret = iniValue(source, username, "secret");
  if (!secret) return null;
  const bind = iniValue(source, "general", "bindaddr");
  const hostname = !bind || bind === "0.0.0.0" || bind === "::" ? "127.0.0.1" : bind;
  const port = Number(iniValue(source, "general", "port")) || 5038;
  return { engine: "asterisk", hostname, port, username, secret };
}

/** ESL password from `event_socket.conf.xml`. */
export function eslPasswordFromConfig(source: string) {
  return source.match(/<param\s+name="password"\s+value="([^"]*)"/i)?.[1] ?? "";
}

function wakes(engine: PresenceEventEngine, text: string) {
  return engine === "asterisk"
    ? /Event:\s*ContactStatus/i.test(text)
    : /Event-Subclass:\s*sofia(?:%3A%3A|::)(?:register|unregister|expire)\b/i.test(text);
}

async function readUntil(
  connection: Connection,
  done: (text: string) => boolean,
  timeoutMs: number,
) {
  const buffer = new Uint8Array(4096);
  let text = "";
  const deadline = Date.now() + timeoutMs;
  while (!done(text)) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error("PABX event login timed out");
    let timer: ReturnType<typeof setTimeout> | undefined;
    const read = await Promise.race([
      connection.read(buffer),
      new Promise<"timeout">((resolve) => {
        timer = setTimeout(() => resolve("timeout"), remaining);
      }),
    ]).finally(() => clearTimeout(timer));
    if (read === "timeout") throw new Error("PABX event login timed out");
    if (read === null) throw new Error("PABX event connection closed");
    text += decoder.decode(buffer.subarray(0, read));
    if (text.length > 65536) text = text.slice(-16384);
  }
  return text;
}

/** Logs in and subscribes; returns what was read after the login reply (it may hold events). */
async function login(connection: Connection, endpoint: EventEndpoint, timeoutMs: number) {
  if (endpoint.engine === "asterisk") {
    await readUntil(connection, (text) => text.includes("Asterisk Call Manager"), timeoutMs);
    await connection.write(encoder.encode(
      `Action: Login\r\nUsername: ${endpoint.username}\r\nSecret: ${endpoint.secret}\r\nEvents: system\r\n\r\n`,
    ));
    const reply = await readUntil(
      connection,
      (text) => /Response:\s*(Success|Error)/i.test(text),
      timeoutMs,
    );
    if (!/Response:\s*Success/i.test(reply)) throw new Error("AMI login refused");
    return reply;
  }
  await readUntil(connection, (text) => text.includes("auth/request"), timeoutMs);
  await connection.write(encoder.encode(`auth ${endpoint.secret}\n\n`));
  const reply = await readUntil(connection, (text) => /Reply-Text:\s*[+-]/i.test(text), timeoutMs);
  if (!/Reply-Text:\s*\+OK/i.test(reply)) throw new Error("ESL authentication refused");
  await connection.write(
    encoder.encode("event plain CUSTOM sofia::register sofia::unregister sofia::expire\n\n"),
  );
  return "";
}

/**
 * Keeps one engine connection alive and calls `onEvent` for each registration event. Returns a
 * stop function. A missing endpoint (engine not managed, no credentials) is retried slowly.
 */
export function listenPabxEvents(options: EventListenerOptions) {
  const connect = options.connect ??
    ((hostname: string, port: number) => Deno.connect({ hostname, port }));
  const retryMs = options.retryMs ?? 5_000;
  const maxRetryMs = options.maxRetryMs ?? 60_000;
  const loginTimeoutMs = options.loginTimeoutMs ?? 10_000;
  let stopped = false;
  let current: Connection | null = null;
  let wakeSleep: (() => void) | null = null;
  const sleep = (ms: number) =>
    new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, ms);
      wakeSleep = () => {
        clearTimeout(timer);
        resolve();
      };
    });

  const loop = async () => {
    let delay = retryMs;
    let lastProblem = "";
    while (!stopped) {
      const endpoint = await options.resolve().catch(() => null);
      if (!endpoint) {
        await sleep(maxRetryMs);
        continue;
      }
      try {
        current = await connect(endpoint.hostname, endpoint.port);
        const early = await login(current, endpoint, loginTimeoutMs);
        options.log("info", "PABX registration events connected.", { engine: endpoint.engine });
        lastProblem = "";
        delay = retryMs;
        // A fresh subscription may have missed changes while disconnected.
        options.onEvent(endpoint.engine);
        // Events may arrive in the same read as the login reply.
        const afterLogin = early.replace(/^[\s\S]*?Response:\s*Success[^\n]*\n/i, "");
        if (wakes(endpoint.engine, afterLogin)) options.onEvent(endpoint.engine);
        const buffer = new Uint8Array(16384);
        let tail = "";
        while (!stopped) {
          const read = await current.read(buffer);
          if (read === null) throw new Error("PABX event connection closed");
          const text = tail + decoder.decode(buffer.subarray(0, read));
          if (wakes(endpoint.engine, text)) options.onEvent(endpoint.engine);
          tail = text.slice(-256);
        }
      } catch (error) {
        const problem = error instanceof Error ? error.message : String(error);
        // One line per new problem; a flapping engine does not flood the journal.
        if (!stopped && problem !== lastProblem) {
          options.log("warn", "PABX registration events unavailable; retrying.", {
            engine: endpoint.engine,
            reason: problem,
          });
          lastProblem = problem;
        }
      } finally {
        try {
          current?.close();
        } catch {
          // already closed
        }
        current = null;
      }
      if (stopped) break;
      await sleep(delay);
      delay = Math.min(delay * 2, maxRetryMs);
    }
  };
  const running = loop();
  return {
    stop: async () => {
      stopped = true;
      try {
        current?.close();
      } catch {
        // already closed
      }
      wakeSleep?.();
      await running;
    },
  };
}

/**
 * Coalesces wake signals: the first event runs `task` after `debounceMs`, never closer than
 * `minIntervalMs` to the previous run, and events during a run schedule exactly one more.
 */
export function coalesce(task: () => Promise<void>, debounceMs = 1_500, minIntervalMs = 5_000) {
  let timer: ReturnType<typeof setTimeout> | null = null;
  let running = false;
  let again = false;
  let lastRun = 0;
  const run = async () => {
    timer = null;
    running = true;
    lastRun = Date.now();
    try {
      await task();
    } catch {
      // the task logs its own failures; the next event or heartbeat retries
    } finally {
      running = false;
      if (again) {
        again = false;
        trigger();
      }
    }
  };
  const trigger = () => {
    if (running) {
      again = true;
      return;
    }
    if (timer) return;
    const wait = Math.max(debounceMs, lastRun + minIntervalMs - Date.now());
    timer = setTimeout(run, wait);
  };
  return {
    trigger,
    cancel: () => {
      if (timer) clearTimeout(timer);
      timer = null;
      again = false;
    },
  };
}
