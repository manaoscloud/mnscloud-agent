// SIP User-Agent (the phone or softphone) of FreeSWITCH registrations.
//
// `show registrations` reads the core registration table, which has no User-Agent. mod_sofia keeps
// it per profile and prints it in `sofia xmlstatus profile <name> reg`; this module parses that
// output and fills `userAgent` on the registrations that lack it. A failed read leaves them as
// they are, so presence and diagnostics never depend on it.

export type FreeSwitchSofiaRegistration = {
  username: string;
  realm: string | null;
  userAgent: string;
  networkIP: string | null;
};

type RegistrationWithUserAgent = {
  username: string;
  domain?: string | null;
  contact?: string | null;
  networkIP?: string | null;
  userAgent?: string | null;
};

const SOFIA_PROFILE = /^[A-Za-z0-9_.-]{1,64}$/;
const MAX_USER_AGENT = 240;

function xmlText(value: string) {
  return value
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&amp;", "&")
    .replace(/\s+/g, " ")
    .trim();
}

function tag(block: string, name: string) {
  const match = new RegExp(String.raw`<${name}>([\s\S]*?)</${name}>`).exec(block);
  return match ? xmlText(match[1]) : "";
}

/** Registrations of one `sofia xmlstatus profile <name> reg` output (malformed blocks skipped). */
export function parseSofiaRegistrationsXml(output: string): FreeSwitchSofiaRegistration[] {
  const registrations: FreeSwitchSofiaRegistration[] = [];
  for (const match of output.matchAll(/<registration>([\s\S]*?)<\/registration>/g)) {
    const block = match[1];
    const userAgent = tag(block, "agent").slice(0, MAX_USER_AGENT);
    const user = tag(block, "user");
    const at = user.lastIndexOf("@");
    const username = tag(block, "sip-auth-user") || (at > 0 ? user.slice(0, at) : user);
    if (!username || !userAgent) continue;
    const realm = tag(block, "sip-auth-realm") || (at > 0 ? user.slice(at + 1) : "");
    registrations.push({
      username,
      realm: realm.toLowerCase() || null,
      userAgent,
      networkIP: tag(block, "network-ip") || null,
    });
  }
  return registrations;
}

/** Sofia profiles named in the registration URLs (`sofia/<profile>/sip:...`), `internal` if none. */
export function sofiaProfiles(registrations: RegistrationWithUserAgent[]): string[] {
  const profiles = new Set<string>();
  for (const item of registrations) {
    const match = /^sofia\/([^/]+)\//.exec(String(item.contact ?? ""));
    if (match && SOFIA_PROFILE.test(match[1])) profiles.add(match[1]);
  }
  if (!profiles.size) profiles.add("internal");
  return [...profiles].sort((a, b) => a.localeCompare(b));
}

/** Fills the missing `userAgent` of each registration (same user and realm, same IP first). */
export function applySofiaUserAgents<T extends RegistrationWithUserAgent>(
  registrations: T[],
  sofia: FreeSwitchSofiaRegistration[],
): T[] {
  if (!sofia.length) return registrations;
  return registrations.map((item) => {
    if (item.userAgent?.trim()) return item;
    const domain = item.domain?.trim().toLowerCase() || null;
    const candidates = sofia.filter((row) =>
      row.username === item.username && (!domain || !row.realm || row.realm === domain)
    );
    const found = candidates.find((row) => item.networkIP && row.networkIP === item.networkIP) ??
      candidates[0];
    return found ? { ...item, userAgent: found.userAgent } : item;
  });
}

/** Reads the Sofia registrations of every profile; a profile that cannot be read is skipped. */
export async function readSofiaRegistrations(
  profiles: string[],
  run: (args: string[]) => Promise<{ code: number; stdout: string }>,
): Promise<FreeSwitchSofiaRegistration[]> {
  const reads = profiles.filter((profile) => SOFIA_PROFILE.test(profile)).map(async (profile) => {
    try {
      const result = await run(["-x", `sofia xmlstatus profile ${profile} reg`]);
      return result.code === 0 ? parseSofiaRegistrationsXml(result.stdout) : [];
    } catch {
      // The User-Agent is informative: a failed read keeps the registrations unchanged.
      return [];
    }
  });
  return (await Promise.all(reads)).flat();
}
