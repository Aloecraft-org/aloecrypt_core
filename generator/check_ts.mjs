// generator/check_ts.mjs
// Exercises the generated TypeScript bindings with a stub plugin, the way
// CI exercises the Python ones. Usage: node generator/check_ts.mjs <compiled .mjs>

import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
const m = await import(pathToFileURL(resolve(process.argv[2])).href);
const stub = (reply) => ({ call: async () => (reply === null ? null : { bytes: () => reply }) });
const ok = (payload) => new Uint8Array([0, 0, ...payload]);
const expectStatus = async (p, code) => {
  try { await p; } catch (e) {
    if (e instanceof m.AloecryptStatusError && e.code === code) return;
    throw new Error(`wrong error: ${e}`);
  }
  throw new Error(`no throw, wanted status ${code}`);
};

// Every struct round-trips at its declared SIZE through a stub Ok reply.
const cred = m.OtpCredential.fromBytes(new Uint8Array(m.OtpCredential.SIZE));
cred.counter = -5n; cred.period = 30n; cred.digits = 6;
const bytes = cred.toBytes();
if (bytes.length !== m.OtpCredential.SIZE) throw new Error("OtpCredential size");
const back = m.OtpCredential.fromBytes(bytes);
if (back.counter !== -5n || back.period !== 30n || back.digits !== 6) throw new Error("signed field round trip");

const out = await m.otp_api___otpcredential__with_counter(cred, 7n, stub(ok(bytes)));
if (!(out instanceof m.OtpCredential) || out.counter !== -5n) throw new Error("&Self return decodes the struct");

// Non-Ok raises with its code; short and truncated replies are Unspecified.
await expectStatus(m.otp_api___otpcredential__with_counter(cred, 7n, stub(new Uint8Array([1, 0]))), 1);
await expectStatus(m.otp_api___otpcredential__with_counter(cred, 7n, stub(new Uint8Array([0]))), 65535);
await expectStatus(m.otp_api___otpcredential__with_counter(cred, 7n, stub(null)), 65535);
await expectStatus(m.otp_api___otpcredential__with_counter(cred, 7n, stub(ok(bytes.slice(0, 10)))), 65535);
console.log("typescript bindings: struct round trip, status prefix, short and truncated replies all pass");
