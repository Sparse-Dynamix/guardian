export type TpfCaseMode = "payload" | "mitm";

export interface TpfSmokeCase {
  name: string;
  mode: TpfCaseMode;
  /** pass | reject | swap | image-swap | absent for passthrough */
  tpf: "" | "pass" | "reject" | "swap" | "image-swap";
  tps?: boolean;
  expectExit: number;
  expectStdoutContains?: string;
  expectStdoutEquals?: string;
  expectStdoutNonempty?: boolean;
  expectStdoutNotContains?: string[];
  expectContentType?: string;
  useStdin?: boolean;
  curlIncludeHeaders?: boolean;
  /** MITM child curl URL override */
  smokeUrl?: string;
  env?: Record<string, string>;
  /** When set, child runs printenv for this variable instead of curl */
  printenvVar?: string;
}

export const tpfSmokeCases: TpfSmokeCase[] = [
  {
    name: "payload_echo",
    mode: "payload",
    tpf: "",
    expectExit: 0,
    expectStdoutEquals: "hello",
  },
  {
    name: "payload_pass",
    mode: "payload",
    tpf: "pass",
    expectExit: 0,
    expectStdoutEquals: "hello",
  },
  {
    name: "payload_reject",
    mode: "payload",
    tpf: "reject",
    expectExit: 1,
    expectStdoutContains: "Blocked by Guardian",
  },
  {
    name: "payload_swap",
    mode: "payload",
    tpf: "swap",
    tps: true,
    expectExit: 0,
    expectStdoutContains: "SWAPPED_BODY",
  },
  {
    name: "payload_stdin_pass",
    mode: "payload",
    tpf: "pass",
    expectExit: 0,
    expectStdoutEquals: "test\n",
    useStdin: true,
  },
  {
    name: "tps_without_tpf_fails",
    mode: "payload",
    tpf: "",
    tps: true,
    expectExit: 1,
  },
  {
    name: "mitm_passthrough",
    mode: "mitm",
    tpf: "",
    expectExit: 0,
    expectStdoutNonempty: true,
  },
  {
    name: "mitm_passthrough_env",
    mode: "mitm",
    tpf: "",
    expectExit: 0,
    env: { CUSTOM_ENV: "smoke-value" },
    printenvVar: "CUSTOM_ENV",
    expectStdoutContains: "smoke-value",
  },
  {
    name: "mitm_pass",
    mode: "mitm",
    tpf: "pass",
    expectExit: 0,
    expectStdoutNonempty: true,
  },
  {
    name: "mitm_reject",
    mode: "mitm",
    tpf: "reject",
    expectExit: 0,
    expectStdoutContains: "Blocked by Guardian",
  },
  {
    name: "mitm_swap",
    mode: "mitm",
    tpf: "swap",
    tps: true,
    expectExit: 0,
    expectStdoutContains: "SWAPPED_BODY",
    curlIncludeHeaders: true,
    expectContentType: "text/markdown",
  },
  {
    name: "mitm_image_swap",
    mode: "mitm",
    tpf: "image-swap",
    tps: true,
    expectExit: 0,
    curlIncludeHeaders: true,
    expectStdoutContains: "swapped by TPF mock",
    expectContentType: "text/markdown",
    expectStdoutNotContains: ["image/png"],
    smokeUrl: process.env.SMOKE_IMAGE_URL ?? "https://httpbingo.org/image/png",
  },
];
