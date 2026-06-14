#!/usr/bin/env zx
import { hostPlatform } from "./lib/guard.ts";
import { packReleaseArchive } from "./lib/release-pack.ts";

const archive = await packReleaseArchive(hostPlatform());
console.log(`packed ${archive}`);
