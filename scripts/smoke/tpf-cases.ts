export type TpfCaseMode = "payload" | "mitm";

export type TpfSmokeTarget =
  | "localHttp"
  | "localLoopback"
  | "localSse"
  | "localImage"
  | "localHttp2"
  | "localHttp2c";

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
  /** MITM curl target */
  target?: TpfSmokeTarget;
  /** Extra curl flags (e.g. --http2) */
  curlExtra?: string[];
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
    expectStdoutContains: "All content chunks flagged",
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
    target: "localHttp",
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
    name: "mitm_loopback_bypass",
    mode: "mitm",
    tpf: "pass",
    expectExit: 0,
    expectStdoutNonempty: true,
    target: "localLoopback",
  },
  {
    name: "mitm_pass",
    mode: "mitm",
    tpf: "pass",
    expectExit: 0,
    expectStdoutNonempty: true,
    target: "localHttp",
  },
  {
    name: "mitm_reject",
    mode: "mitm",
    tpf: "reject",
    expectExit: 0,
    expectStdoutContains: "All content chunks flagged",
    target: "localHttp",
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
    target: "localHttp",
  },
  {
    name: "mitm_http2",
    mode: "mitm",
    tpf: "pass",
    expectExit: 0,
    expectStdoutNonempty: true,
    target: "localHttp2",
    curlExtra: ["--http2"],
  },
  {
    name: "mitm_http2_tpf",
    mode: "mitm",
    tpf: "pass",
    expectExit: 0,
    expectStdoutNonempty: true,
    target: "localHttp2",
    curlExtra: ["--http2"],
  },
  {
    name: "mitm_sse_streaming",
    mode: "mitm",
    tpf: "pass",
    expectExit: 0,
    expectStdoutContains: "event: ping",
    target: "localSse",
    curlExtra: ["--max-time", "6"],
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
    target: "localImage",
  },
];
