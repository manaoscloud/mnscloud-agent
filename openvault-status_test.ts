import {
  collectOpenVaultStatus,
  parseEnv,
  parseOpenSslEndDate,
  stateFromSealStatus,
} from "./openvault-status.ts";

function assertEquals(actual: unknown, expected: unknown) {
  const [a, e] = [JSON.stringify(actual), JSON.stringify(expected)];
  if (a !== e) throw new Error(`Assertion failed: ${a} !== ${e}`);
}

Deno.test("seal-status maps to runtime states", () => {
  assertEquals(stateFromSealStatus({ type: "awskms", initialized: true, sealed: false }), {
    state: "unsealed",
    sealType: "awskms",
  });
  assertEquals(
    stateFromSealStatus({ type: "shamir", initialized: true, sealed: true }).state,
    "sealed",
  );
  assertEquals(stateFromSealStatus({ initialized: false, sealed: true }).state, "uninitialized");
  assertEquals(stateFromSealStatus(null).state, "unreachable");
  assertEquals(stateFromSealStatus({ type: "bad type!", sealed: false }).sealType, null);
});

Deno.test("env and openssl parsing", () => {
  assertEquals(
    parseEnv("# c\nexport OPENVAULT_API_ADDR='https://10.0.0.1:8200'\nOPENVAULT_SEAL=awskms\n"),
    { OPENVAULT_API_ADDR: "https://10.0.0.1:8200", OPENVAULT_SEAL: "awskms" },
  );
  assertEquals(parseOpenSslEndDate("notAfter=Oct 27 03:25:50 2026 GMT\n"), "2026-10-27T03:25:50Z");
  assertEquals(parseOpenSslEndDate("garbage"), null);
});

Deno.test("collector reports unsealed, unreachable and absent hosts", async () => {
  const files: Record<string, string> = {
    "/env": "OPENVAULT_API_ADDR=https://10.0.0.1:8200\nOPENVAULT_SEAL=awskms\n",
    "/etc/mnscloud/openvault/tls/server.crt": "PEM",
  };
  const readTextFile = (path: string) =>
    path in files ? Promise.resolve(files[path]) : Promise.reject(new Error("missing"));
  const endDate = () => Promise.resolve("2026-10-27T03:25:50Z");
  let url = "";
  const ok = await collectOpenVaultStatus("/env", {
    readTextFile,
    endDate,
    sealStatus: (target, ca) => {
      url = `${target}|${ca}`;
      return Promise.resolve({ type: "awskms", initialized: true, sealed: false });
    },
  });
  assertEquals(ok, { state: "unsealed", sealType: "awskms", tlsNotAfter: "2026-10-27T03:25:50Z" });
  assertEquals(url, "https://10.0.0.1:8200/v1/sys/seal-status|PEM");
  const down = await collectOpenVaultStatus("/env", {
    readTextFile,
    endDate,
    sealStatus: () => Promise.reject(new Error("refused")),
  });
  assertEquals(down, {
    state: "unreachable",
    sealType: "awskms",
    tlsNotAfter: "2026-10-27T03:25:50Z",
  });
  files["/private"] = "OPENVAULT_PRIVATE_HOST=172.17.0.176\nOPENVAULT_TLS_MODE=self-signed\n";
  await collectOpenVaultStatus("/private", {
    readTextFile,
    endDate,
    sealStatus: (target) => {
      url = target;
      return Promise.resolve({ type: "shamir", initialized: true, sealed: true });
    },
  });
  assertEquals(url, "https://172.17.0.176:8200/v1/sys/seal-status");
  assertEquals(
    await collectOpenVaultStatus("/absent", {
      readTextFile,
      endDate,
      sealStatus: () => Promise.resolve({}),
    }),
    null,
  );
});
