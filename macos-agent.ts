/**
 * macOS Agent helpers (V10a): the one-shot launchd job of the self-update. The Agent runs as the
 * LaunchDaemon `cloud.manaos.mnscloud.agent`; the update runs in its own job so restarting the
 * Agent does not kill it.
 */

function shellQuote(value: string) {
  return `'${value.replaceAll("'", String.raw`'\''`)}'`;
}

export const MACOS_UPDATE_LABEL = "cloud.manaos.mnscloud.agent-update";

/** launchd property list of the one-shot update job. */
export function macosUpdatePlist(repoDir: string, targetRef: string) {
  const escape = (value: string) =>
    value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  const command = [
    "sleep 2",
    `cd ${shellQuote(repoDir)}`,
    `/bin/bash scripts/update-agent-macos.sh --ref ${shellQuote(targetRef)}`,
  ].join(" && ");
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<plist version="1.0">',
    "<dict>",
    `  <key>Label</key><string>${MACOS_UPDATE_LABEL}</string>`,
    "  <key>ProgramArguments</key>",
    "  <array>",
    "    <string>/bin/bash</string>",
    "    <string>-lc</string>",
    `    <string>${escape(command)}</string>`,
    "  </array>",
    "  <key>RunAtLoad</key><true/>",
    "  <key>LaunchOnlyOnce</key><true/>",
    "  <key>AbandonProcessGroup</key><true/>",
    "  <key>StandardOutPath</key><string>/var/log/mnscloud/agent/update.log</string>",
    "  <key>StandardErrorPath</key><string>/var/log/mnscloud/agent/update.log</string>",
    "</dict>",
    "</plist>",
    "",
  ].join("\n");
}
