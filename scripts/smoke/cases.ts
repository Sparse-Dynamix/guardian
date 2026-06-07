export type SmokeCommand = "direct" | "child";

export interface SmokeCase {
  name: string;
  command: SmokeCommand;
  silent: boolean;
  expectExit: number;
  expectJsonlType: "" | "http";
  expectStdoutNonempty: boolean;
}

export const smokeCases: SmokeCase[] = [
  {
    name: "direct_https",
    command: "direct",
    silent: false,
    expectExit: 0,
    expectJsonlType: "http",
    expectStdoutNonempty: true,
  },
  {
    name: "child_spawn",
    command: "child",
    silent: false,
    expectExit: 0,
    expectJsonlType: "http",
    expectStdoutNonempty: true,
  },
  {
    name: "silent",
    command: "direct",
    silent: true,
    expectExit: 0,
    expectJsonlType: "",
    expectStdoutNonempty: true,
  },
];
