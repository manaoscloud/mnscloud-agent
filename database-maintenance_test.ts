import { assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  DATABASE_MAINTENANCE_TABLES,
  hasRebuildDiskSpace,
  optimizeSucceeded,
  parseBatchRows,
  parseDfAvailable,
  parseMaintenanceEnv,
  selectMaintenanceTables,
} from "./database-maintenance.ts";

Deno.test("maintenance tables default to the allowlist and reject anything else", () => {
  assertEquals(selectMaintenanceTables(undefined), [...DATABASE_MAINTENANCE_TABLES]);
  assertEquals(selectMaintenanceTables(["FreeSwitchCdr", "FreeSwitchCdr"]), ["FreeSwitchCdr"]);
  assertThrows(() => selectMaintenanceTables(["User"]), Error, "not allowlisted");
  assertThrows(() => selectMaintenanceTables(["FreeSwitchCdr`; DROP"]), Error, "not allowlisted");
  assertThrows(() => selectMaintenanceTables([]), Error, "non-empty");
});

Deno.test("maintenance env reads only the root password and a safe database name", () => {
  const env = parseMaintenanceEnv(
    "# comment\nexport DB_ROOT_PASSWORD='s3cr=t'\nDB_NAME=\"clouddb\"\nOTHER=1\n",
  );
  assertEquals(env, { password: "s3cr=t", database: "clouddb" });
  assertThrows(() => parseMaintenanceEnv("DB_NAME=clouddb\n"), Error, "DB_ROOT_PASSWORD");
  assertThrows(
    () => parseMaintenanceEnv("DB_ROOT_PASSWORD=x\nDB_NAME=cloud;db\n"),
    Error,
    "DB_NAME",
  );
});

Deno.test("rebuild requires 1.2x the table size in free disk", () => {
  assertEquals(hasRebuildDiskSpace(1200, 1000), true);
  assertEquals(hasRebuildDiskSpace(1199, 1000), false);
  assertEquals(hasRebuildDiskSpace(Number.NaN, 1000), false);
});

Deno.test("OPTIMIZE TABLE and df output parsing", () => {
  const rows = parseBatchRows(
    "clouddb.FreeSwitchCdr\toptimize\tnote\tTable does not support optimize, doing recreate + analyze instead\nclouddb.FreeSwitchCdr\toptimize\tstatus\tOK\n",
  );
  assertEquals(optimizeSucceeded(rows), { ok: true, message: "OK" });
  assertEquals(
    optimizeSucceeded([["t", "optimize", "error", "Disk full"]]).ok,
    false,
  );
  assertEquals(parseDfAvailable("   Avail\n15032385536\n"), 15032385536);
  assertEquals(Number.isNaN(parseDfAvailable("Avail\n")), true);
});
