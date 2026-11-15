// Minimal type declarations for snarkjs (it ships no TypeScript types).
// Widened vs the Gatekeeper copy: fullProve inputs may include an array
// value (strategyParams is an array of 8 field elements).
declare module "snarkjs" {
  export namespace groth16 {
    function fullProve(
      input: Record<string, string | number | bigint | string[]>,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    function verify(
      vkey: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
  }
}
