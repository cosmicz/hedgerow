// Runtime pins for the sponsor proof. fetch.sh carries the same values for
// downloads; tests/sponsors/pins.test.ts keeps the two in step.
import { join } from "node:path";

export const PINS = {
  clickhouse: {
    version: "26.8.22.13",
    binary: "clickhouse-26.8.22.13",
    sha256: "015a56230b2474fa13e39f627e8f7ba6155fa9c666419646354173bd869e1c54",
  },
  mongodb: {
    version: "8.0.4",
    binary: "mongodb-macos-aarch64-8.0.4/bin/mongod",
    sha256: "bb19b23779e82b36ed620dbccb653c00d262b54134ad3359856a96f2575af8e1",
    archive_sha256: "219e3b3d7b31c049ff7bcf7470d38eff704e56df2ac18d4df78425e2985ccf58",
  },
  semgrep: { version: "1.180.0" },
} as const;

export interface BinaryDigest {
  readonly binary: string;
  readonly expected_sha256: string;
  readonly actual_sha256: string | null;
  readonly matches: boolean;
}

/** Hashes the pinned binaries in RG_SPONSOR_TOOLS; a missing directory or file never matches. */
export async function verifyBinaries(toolsDir: string | undefined): Promise<readonly BinaryDigest[]> {
  return Promise.all(
    [PINS.clickhouse, PINS.mongodb].map(async (pin) => {
      const file = toolsDir ? Bun.file(join(toolsDir, pin.binary)) : null;
      const actual = file && (await file.exists())
        ? new Bun.CryptoHasher("sha256").update(await file.arrayBuffer()).digest("hex")
        : null;
      return { binary: pin.binary, expected_sha256: pin.sha256, actual_sha256: actual, matches: actual === pin.sha256 };
    }),
  );
}
