export type TpfCaseMode = "payload" | "mitm";

export interface TpfSmokeCase {
  name: string;
  mode: TpfCaseMode;
  /** "pass" | "reject" | absent for passthrough */
  tpf: "" | "pass" | "reject";
  expectExit: number;
  expectStdoutContains?: string;
  expectStdoutEquals?: string;
  expectStdoutNonempty?: boolean;
  useStdin?: boolean;
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
    expectStdoutContains: '"safe":true',
  },
  {
    name: "payload_reject",
    mode: "payload",
    tpf: "reject",
    expectExit: 1,
    expectStdoutContains: "Blocked by Guardian",
  },
  {
    name: "payload_stdin_pass",
    mode: "payload",
    tpf: "pass",
    expectExit: 0,
    expectStdoutContains: '"safe":true',
    useStdin: true,
  },
  {
    name: "mitm_passthrough",
    mode: "mitm",
    tpf: "",
    expectExit: 0,
    expectStdoutNonempty: true,
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
];
