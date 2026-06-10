export type SmokeCommand = "direct" | "child" | "interrupt";

export interface SmokeCase {
  name: string;
  command: SmokeCommand;
  expectExit: number;
  expectStdoutNonempty: boolean;
}

export const smokeCases: SmokeCase[] = [
  {
    name: "direct_https",
    command: "direct",
    expectExit: 0,
    expectStdoutNonempty: true,
  },
  {
    name: "child_spawn",
    command: "child",
    expectExit: 0,
    expectStdoutNonempty: true,
  },
  {
    name: "interrupt_teardown",
    command: "interrupt",
    expectExit: 130,
    expectStdoutNonempty: false,
  },
];
