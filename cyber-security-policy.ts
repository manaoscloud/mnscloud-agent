/**
 * Cyber Security host policy helpers (pure, unit tested in cyber-security-policy_test.ts).
 *
 * - Protection levels (`basic`, `balanced`, `strict`) with a real effect.
 * - Allowlist and trusted networks as a CrowdSec whitelist parser.
 * - Blocklist entries as CrowdSec decisions owned by the Agent (reason `mnscloud-list`).
 * - CrowdSec package repository configured by the Agent with signing keys pinned by fingerprint,
 *   instead of running a remote installation script.
 */

export const CROWDSEC_WHITELIST_PATH = "/etc/crowdsec/parsers/s02-enrich/mnscloud-whitelist.yaml";
export const CROWDSEC_LIST_REASON = "mnscloud-list";
/** Duration of a blocklist entry without expiry; every profile apply refreshes it. */
export const CROWDSEC_LIST_DEFAULT_DURATION = "8760h";
export const CROWDSEC_LEVEL_BASIC_COLLECTIONS = [
  "crowdsecurity/linux",
  "crowdsecurity/sshd",
];

/**
 * Primary key fingerprints accepted for the CrowdSec packagecloud repository (checked
 * 2026-11-06): the packagecloud repository key (APT metadata and RPM repository metadata) and the
 * CrowdSec RPM signing keys. A downloaded key with any other primary fingerprint is refused.
 */
export const CROWDSEC_REPOSITORY_KEY_FINGERPRINTS = [
  "6A89E3C2303A901A889971D3376ED5326E93CD0C",
  "79B8CC3F94472AC862A8AD8DB06F1981145CE2F2",
  "9082D8CACBBEB0DAB218BAB04C3D386C3CDF0DB4",
];
const CROWDSEC_REPOSITORY_BASE = "https://packagecloud.io/crowdsec/crowdsec";
const CROWDSEC_RPM_KEY_IDS = ["C822EDD6B39954A1", "FED78314A2468CCF"];

export type CrowdSecLevel = "basic" | "balanced" | "strict" | "custom";

export type CrowdSecLevelPolicy = {
  /** Only the SSH service is acquired and only the OS/SSH collections are installed. */
  osOnly: boolean;
  /** MNSCloud scenarios (SIP/FreeSWITCH/Asterisk) are installed. */
  strictScenarios: boolean;
};

export function crowdSecLevelPolicy(level: string): CrowdSecLevelPolicy {
  if (level === "basic") return { osOnly: true, strictScenarios: false };
  if (level === "strict") return { osOnly: false, strictScenarios: true };
  return { osOnly: false, strictScenarios: false };
}

/** Services and collections the level keeps from the profile. */
export function crowdSecLevelSelection<T extends { slug?: unknown }>(
  level: string,
  services: T[],
  collections: string[],
) {
  if (!crowdSecLevelPolicy(level).osOnly) return { services, collections };
  return {
    services: services.filter((service) =>
      typeof service?.slug === "string" && service.slug.trim().toLowerCase() === "ssh"
    ),
    collections: [...CROWDSEC_LEVEL_BASIC_COLLECTIONS],
  };
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** IPv4/IPv6 address or CIDR; the API validates too, the Agent never trusts the payload alone. */
export function hostNetwork(value: unknown): { value: string; cidr: boolean } | null {
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (!text || text.length > 64 || !/^[0-9a-fA-F:./]+$/.test(text)) return null;
  const [address, prefix, extra] = text.split("/");
  if (extra !== undefined) return null;
  const v4 = IPV4.test(address);
  const v6 = !v4 && address.includes(":") && (address.match(/::/g) ?? []).length <= 1 &&
    address.split(":").every((group) => group === "" || /^[0-9a-fA-F]{1,4}$/.test(group));
  if (!v4 && !v6) return null;
  if (prefix === undefined) return { value: address.toLowerCase(), cidr: false };
  if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > (v4 ? 32 : 128)) return null;
  return { value: `${address.toLowerCase()}/${Number(prefix)}`, cidr: true };
}

function uniqueNetworks(values: unknown[]) {
  const seen = new Map<string, { value: string; cidr: boolean }>();
  for (const value of values) {
    const network = hostNetwork(value);
    if (network) seen.set(network.value, network);
  }
  return [...seen.values()];
}

/** CrowdSec whitelist parser for the allowlist and trusted networks; null removes the file. */
export function crowdSecWhitelistContent(allowlist: unknown[], trustedNetworks: unknown[]) {
  const networks = uniqueNetworks([...allowlist, ...trustedNetworks]);
  if (networks.length === 0) return null;
  const ips = networks.filter((network) => !network.cidr).map((network) => network.value);
  const cidrs = networks.filter((network) => network.cidr).map((network) => network.value);
  const lines = [
    "# Managed by MNSCloud Agent. Do not edit manually.",
    "name: mnscloud/whitelist",
    'description: "MNSCloud Cyber Security allowlist and trusted networks"',
    "whitelist:",
    '  reason: "mnscloud allowlist"',
  ];
  if (ips.length) lines.push("  ip:", ...ips.map((ip) => `    - ${JSON.stringify(ip)}`));
  if (cidrs.length) {
    lines.push("  cidr:", ...cidrs.map((cidr) => `    - ${JSON.stringify(cidr)}`));
  }
  return lines.join("\n") + "\n";
}

export type BlocklistEntry = { value: string; expiresAt?: string | null };
export type ManagedDecision = { id: number; value: string };

/** Decisions this Agent added for blocklist entries, read from `cscli decisions list -o json`. */
export function managedListDecisions(alerts: Array<Record<string, unknown>>): ManagedDecision[] {
  const decisions: ManagedDecision[] = [];
  for (const alert of alerts) {
    const list = Array.isArray(alert?.["decisions"]) ? alert["decisions"] as unknown[] : [alert];
    for (const item of list) {
      if (!item || typeof item !== "object") continue;
      const decision = item as Record<string, unknown>;
      if (decision["origin"] !== "cscli" || decision["scenario"] !== CROWDSEC_LIST_REASON) continue;
      const id = Number(decision["id"]);
      const network = hostNetwork(decision["value"]);
      if (Number.isInteger(id) && id > 0 && network) decisions.push({ id, value: network.value });
    }
  }
  return decisions;
}

/** Duration until the entry expires (whole hours, at least 1h), or the default for no expiry. */
export function blocklistDuration(expiresAt: string | null | undefined, now = new Date()) {
  if (!expiresAt) return CROWDSEC_LIST_DEFAULT_DURATION;
  const end = Date.parse(expiresAt.endsWith("Z") ? expiresAt : `${expiresAt}Z`);
  if (!Number.isFinite(end)) return CROWDSEC_LIST_DEFAULT_DURATION;
  const hours = Math.ceil((end - now.getTime()) / 3_600_000);
  return hours <= 0 ? null : `${Math.min(hours, 8760)}h`;
}

/**
 * cscli argument lists that converge the host to the desired blocklist: every desired entry is
 * (re)added so its duration is refreshed, and managed decisions no longer desired are deleted by id.
 * Decisions created by CrowdSec scenarios or by hand are never touched.
 */
export function blocklistCommands(
  desired: BlocklistEntry[],
  current: ManagedDecision[],
  now = new Date(),
) {
  const wanted = new Map<string, { cidr: boolean; duration: string }>();
  for (const entry of desired) {
    const network = hostNetwork(entry?.value);
    const duration = blocklistDuration(entry?.expiresAt ?? null, now);
    if (network && duration) wanted.set(network.value, { cidr: network.cidr, duration });
  }
  const remove = current.filter((decision) => !wanted.has(decision.value));
  const keep = new Set(current.filter((decision) => wanted.has(decision.value)));
  return {
    deletes: [
      ...remove,
      // Re-adding refreshes the duration; drop the older managed decision for the same value.
      ...[...keep],
    ].map((decision) => ["decisions", "delete", "--id", String(decision.id)]),
    adds: [...wanted].map(([value, entry]) => [
      "decisions",
      "add",
      entry.cidr ? "--range" : "--ip",
      value,
      "--duration",
      entry.duration,
      "--type",
      "ban",
      "--reason",
      CROWDSEC_LIST_REASON,
    ]),
    removed: remove.map((decision) => decision.value),
    applied: [...wanted.keys()],
  };
}

function fingerprintCheck(file: string) {
  const allowed = CROWDSEC_REPOSITORY_KEY_FINGERPRINTS.join(" ");
  return [
    `fpr="$(gpg --batch --show-keys --with-colons ${file} | awk -F: '$1=="fpr"{print $10; exit}')"`,
    `case " ${allowed} " in *" $fpr "*) ;; *) echo "Unexpected CrowdSec repository key fingerprint: $fpr" >&2; exit 1 ;; esac`,
  ];
}

/**
 * Shell script that configures the official CrowdSec repository with pinned signing keys.
 * Debian/Ubuntu: APT source signed-by a dearmored keyring. RHEL family: yum repository with
 * repository and package GPG checks against local key files.
 */
export function crowdSecRepositorySetupScript(family: "debian" | "rhel") {
  const lines = [
    "set -eu",
    "umask 022",
    'tmp="$(mktemp -d)"',
    "trap 'rm -rf \"$tmp\"' EXIT",
    `curl -fsSL --proto '=https' --tlsv1.2 ${CROWDSEC_REPOSITORY_BASE}/gpgkey -o "$tmp/repo.asc"`,
    ...fingerprintCheck('"$tmp/repo.asc"'),
  ];
  if (family === "debian") {
    lines.push(
      "install -d -m 0755 /etc/apt/keyrings",
      'gpg --batch --yes --dearmor -o /etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg "$tmp/repo.asc"',
      "chmod 0644 /etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg",
      `printf '%s\\n' 'deb [signed-by=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg] ${CROWDSEC_REPOSITORY_BASE}/any/ any main' > /etc/apt/sources.list.d/crowdsec_crowdsec.list`,
      "DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::ForceIPv4=true update -y",
    );
    return lines.join("\n");
  }
  const keyFiles = ["/etc/pki/rpm-gpg/RPM-GPG-KEY-crowdsec-repository"];
  lines.push(
    "install -d -m 0755 /etc/pki/rpm-gpg",
    `install -m 0644 "$tmp/repo.asc" ${keyFiles[0]}`,
  );
  for (const keyID of CROWDSEC_RPM_KEY_IDS) {
    const file = `"$tmp/${keyID}.asc"`;
    const target = `/etc/pki/rpm-gpg/RPM-GPG-KEY-crowdsec-${keyID}`;
    lines.push(
      `curl -fsSL --proto '=https' --tlsv1.2 ${CROWDSEC_REPOSITORY_BASE}/gpgkey/crowdsec-crowdsec-${keyID}.pub.gpg -o ${file}`,
      ...fingerprintCheck(file),
      `install -m 0644 ${file} ${target}`,
    );
    keyFiles.push(target);
  }
  const gpgKeys = keyFiles.map((file) => `file://${file}`).join(" ");
  lines.push(
    "cat > /etc/yum.repos.d/crowdsec_crowdsec.repo <<'MNSCLOUD_REPO'",
    "[crowdsec_crowdsec]",
    "name=crowdsec_crowdsec",
    `baseurl=${CROWDSEC_REPOSITORY_BASE}/rpm_any/rpm_any/$basearch`,
    "repo_gpgcheck=1",
    "gpgcheck=1",
    "enabled=1",
    `gpgkey=${gpgKeys}`,
    "sslverify=1",
    "metadata_expire=300",
    "MNSCLOUD_REPO",
    "dnf -y makecache --repo crowdsec_crowdsec",
  );
  return lines.join("\n");
}
