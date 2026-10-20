// logs.config.refresh: the API asks the bound Logs node to pull its configuration now (push
// revocation, decision C2). The job carries no command or path: the Agent only starts the node's
// own configuration unit, which pulls GET /logs/runtime/config through this Agent's identity.

export const LOGS_REFRESH_JOB_TYPE = "logs.config.refresh";
export const LOGS_CONFIG_UNIT = "mnscloud-logs-config.service";
const UNIT_PATHS = [
  `/etc/systemd/system/${LOGS_CONFIG_UNIT}`,
  `/lib/systemd/system/${LOGS_CONFIG_UNIT}`,
  `/usr/lib/systemd/system/${LOGS_CONFIG_UNIT}`,
];

export type CommandRunner = (args: string[]) => Promise<boolean>;

/** True when the node unit exists and was started (non-blocking: the 60 s timer stays as fallback). */
export async function runLogsRefresh(
  run: CommandRunner,
  exists: (path: string) => Promise<boolean> = async (path) =>
    Boolean(await Deno.stat(path).catch(() => null)),
): Promise<boolean> {
  let installed = false;
  for (const path of UNIT_PATHS) {
    if (await exists(path)) {
      installed = true;
      break;
    }
  }
  if (!installed) return false;
  return await run(["systemctl", "start", "--no-block", LOGS_CONFIG_UNIT]);
}
