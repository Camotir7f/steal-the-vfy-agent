// Proof child process — runs snarkjs groth16.fullProve in a SEPARATE Node
// process and prints exactly one JSON line to stdout.
//
// WHY A CHILD PROCESS (not the main thread, not a worker thread):
// - snarkjs proving is synchronous CPU work. On the main thread a JS
//   setTimeout CANNOT interrupt a stalled prove, so a stall would block
//   the server's event loop and the response deadline.
// - A worker thread does NOT work: snarkjs depends on ffjavascript, which
//   depends on the `web-worker` package, and that polyfill breaks inside a
//   worker thread ("Worker is not a constructor", verified 2026-11-15).
// - A child process is a full Node instance, so ffjavascript works exactly
//   as on the main thread (proven by the 1.9 s main-thread prove). The
//   parent can SIGKILL the child on timeout, so the prove is genuinely
//   bounded, and the parent's event loop stays responsive.
//
// Protocol (stdin -> stdout, one JSON line each):
//   in:  { "inputs": {...}, "wasmPath": "...", "zkeyPath": "..." }
//   out: { "ok": true, "proof": {...}, "publicSignals": ["..."] }
//        { "ok": false, "error": "..." }
//
// The child calls process.exit() explicitly after writing the result:
// ffjavascript leaves worker threads alive that would otherwise keep the
// process running forever (observed: a child that finished its proof in
// ~2 s CPU still had not exited after 180 s wall). The result is written
// with fs.writeSync so it is flushed before the exit.
//
// The child never logs anything. The inputs contain the private salt +
// params; they arrive on stdin and are never written to disk.
import { writeSync } from "node:fs";
import * as snarkjs from "snarkjs";

async function main() {
  let data = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) data += chunk;
  const { inputs, wasmPath, zkeyPath } = JSON.parse(data);
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      wasmPath,
      zkeyPath,
    );
    writeSync(1, JSON.stringify({ ok: true, proof, publicSignals }) + "\n");
    process.exit(0);
  } catch (err) {
    writeSync(
      1,
      JSON.stringify({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      }) + "\n",
    );
    process.exit(1);
  }
}

main().catch((err) => {
  try {
    writeSync(
      1,
      JSON.stringify({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      }) + "\n",
    );
  } catch {
    // stdout already gone — nothing more we can do.
  }
  process.exit(1);
});
