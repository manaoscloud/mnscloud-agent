/** Bounded engine channel-start peak. It is not offered SIP calls per second. */
export class VoipRateWindow {
  private connectedAt: number | null = null;
  private acknowledgedAt: number | null = null;
  private buckets = new Map<number, number>();
  connect(now: number) {
    this.connectedAt = now;
    this.acknowledgedAt = now;
    this.buckets.clear();
  }
  disconnect() {
    this.connectedAt = null;
    this.acknowledgedAt = null;
    this.buckets.clear();
  }
  acknowledge(now: number) {
    if (this.connectedAt !== null) this.acknowledgedAt = now;
  }
  record(now: number) {
    if (this.connectedAt === null) return;
    const second = Math.floor(now / 1000);
    for (const key of this.buckets.keys()) if (key < second - 60) this.buckets.delete(key);
    const count = (this.buckets.get(second) ?? 0) + 1;
    if (count > 1000000 || now < this.connectedAt) {
      this.disconnect();
      return;
    }
    this.buckets.set(second, count);
    if (this.buckets.size > 61) this.disconnect();
  }
  sample(now: number): number | null {
    if (
      this.connectedAt === null || this.acknowledgedAt === null || now < this.acknowledgedAt ||
      now - this.connectedAt < 61000 || now - this.acknowledgedAt > 15000
    ) return null;
    const second = Math.floor(now / 1000);
    let peak = 0;
    for (const [key, value] of this.buckets) {
      if (key < second - 60) this.buckets.delete(key);
      else if (key < second) peak = Math.max(peak, value);
    }
    return peak;
  }
}

/** Frame by wire bytes, not regex matches across overlapping chunks. Discard identifiers immediately. */
export class VoipEventFrames {
  private buffer = new Uint8Array();
  constructor(private engine: "asterisk" | "freeswitch") {}
  push(chunk: Uint8Array): { channelStarts: number; acknowledgements: number } {
    if (this.buffer.length + chunk.length > 262144) {
      throw new Error("VoIP event frame budget exceeded");
    }
    const next = new Uint8Array(this.buffer.length + chunk.length);
    next.set(this.buffer);
    next.set(chunk, this.buffer.length);
    this.buffer = next;
    let channelStarts = 0, acknowledgements = 0;
    const decoder = new TextDecoder();
    while (this.buffer.length) {
      let end = -1, separator = 0;
      for (let i = 0; i < this.buffer.length - 1; i++) {
        if (this.buffer[i] === 10 && this.buffer[i + 1] === 10) {
          end = i;
          separator = 2;
          break;
        }
        if (
          i + 3 < this.buffer.length && this.buffer[i] === 13 && this.buffer[i + 1] === 10 &&
          this.buffer[i + 2] === 13 && this.buffer[i + 3] === 10
        ) {
          end = i;
          separator = 4;
          break;
        }
      }
      if (end < 0) break;
      const header = decoder.decode(this.buffer.subarray(0, end));
      let bodyLength = 0;
      if (this.engine === "freeswitch") {
        const length = /^Content-Length:\s*(\d+)\s*$/mi.exec(header);
        bodyLength = length ? Number(length[1]) : 0;
        if (!Number.isSafeInteger(bodyLength) || bodyLength > 131072) {
          throw new Error("VoIP event body budget exceeded");
        }
      }
      const size = end + separator + bodyLength;
      if (this.buffer.length < size) break;
      const body = decoder.decode(this.buffer.subarray(end + separator, size));
      this.buffer = this.buffer.slice(size);
      if (this.engine === "asterisk") {
        if (/^Event:\s*Newchannel\s*$/mi.test(header)) channelStarts++;
        if (
          /^ActionID:\s*mnscloud-load-health\s*$/mi.test(header) &&
          /^Ping:\s*Pong\s*$/mi.test(header)
        ) acknowledgements++;
      } else {
        if (
          /^Content-Type:\s*text\/event-plain\s*$/mi.test(header) &&
          /^Event-Name:\s*CHANNEL_CREATE\s*$/mi.test(body)
        ) channelStarts++;
        if (/^Content-Type:\s*api\/response\s*$/mi.test(header) && /^\d+\s*$/.test(body)) {
          acknowledgements++;
        }
      }
    }
    return { channelStarts, acknowledgements };
  }
}
