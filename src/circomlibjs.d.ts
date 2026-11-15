// Minimal type declarations for circomlibjs (it ships no TypeScript types).
// Only buildPoseidon is used (see src/commitment.ts).
declare module "circomlibjs" {
  export interface PoseidonField {
    toString(x: Uint8Array): string;
  }
  export type PoseidonFn = ((inputs: (bigint | number)[]) => Uint8Array) & {
    F: PoseidonField;
  };
  export function buildPoseidon(): Promise<PoseidonFn>;
}
