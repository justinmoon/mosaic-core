# Mosaic Core

This library is a reference implementation for the Mosaic protocol.

## About versions

Until version 1.0.0, the version of this software will match the version of the
[Mosaic spec](https://mikedilger.github.io/mosaic-spec/) that it implements,
except for the patch level.

The patch level will increment on every commit regardless of the kind of change.
But it will reset to 0 when the minor version increments along with the spec version.

After version 1.0.0 [Semantic Versioning](semver.org) rules will be in force.
(Strictly speaking they already are because semver specifies "4. Major version zero
(0.y.z) is for initial development. Anything MAY change at any time. The public API
SHOULD NOT be considered stable."

## Features

- `serde`: enables serde support for data types. Note that they serialize into human
    readable formats, not binary compact formats. Serde doesn't give us any way to
    specify what we really want here when implementing `Serialize` and `Deserialize`,
    and we can't do it both ways. Since most data structures are implemented as sequences
    of bytes, they are sort-of already serialized compactly as bytes.
- `json`: enables functions to convert data types to and from JSON format. Also enables
    `serde`.
