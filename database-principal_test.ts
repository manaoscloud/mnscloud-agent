import { assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  databaseAdapterInput,
  forwardedErrorCode,
  MODULE_DATABASE_CREDENTIAL_ADAPTERS,
  moduleAdapterInput,
  parseDatabasePrincipalJob,
} from "./database-principal.ts";

const lease = "11111111-2222-3333-4444-555555555555";
const material = {
  principalUUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  step: "create",
  profile: "workers",
  username: "Qx7Lm2Pa9Rt4Kc8Z",
  password: "p".repeat(64),
  host: "10.20.0.8",
  databaseName: "clouddb",
  databaseHost: "10.20.0.2",
  databasePort: 3306,
  dbReleaseTag: "v0.1.480",
  schemaSha256: "a".repeat(64),
};

Deno.test("principal jobs carry a lease and a known step", () => {
  assertEquals(
    parseDatabasePrincipalJob({
      jobUUID: material.principalUUID,
      payload: { leaseUUID: lease, step: "deliver" },
    })
      .step,
    "deliver",
  );
  assertThrows(() =>
    parseDatabasePrincipalJob({
      jobUUID: material.principalUUID,
      payload: { leaseUUID: lease, step: "sql" },
    })
  );
  assertThrows(() =>
    parseDatabasePrincipalJob({ jobUUID: "x", payload: { leaseUUID: lease, step: "create" } })
  );
});

Deno.test("only fixed adapter codes are forwarded", () => {
  assertEquals(
    forwardedErrorCode("deliver", "MODULE_DATABASE_ENDPOINT_MISMATCH"),
    "MODULE_DATABASE_ENDPOINT_MISMATCH",
  );
  assertEquals(
    forwardedErrorCode("deliver", "Access denied for user"),
    "MODULE_DATABASE_CREDENTIAL_FAILED",
  );
  assertEquals(forwardedErrorCode("create", undefined), "DATABASE_PRINCIPAL_PROVISION_FAILED");
});

Deno.test("adapters receive only the fields they read", () => {
  const revoke = databaseAdapterInput(material, "revoke");
  assertEquals("password" in revoke, false, "revocation never carries the secret");
  assertEquals("dbReleaseTag" in revoke, false);
  assertEquals(databaseAdapterInput(material, "create").password, material.password);
  assertEquals(Object.keys(moduleAdapterInput(material)).sort(), [
    "databaseHost",
    "databaseName",
    "databasePort",
    "password",
    "username",
  ]);
  assertEquals(Object.keys(MODULE_DATABASE_CREDENTIAL_ADAPTERS).sort(), ["api", "workers"]);
});
