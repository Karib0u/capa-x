# Differential test report

Measured 2026-10-20 against capa-x `385b24e` and the reference pins in
`PINNED.md`. See [the validation summary](full-corpus-2026-10-20.md) for scope
and the distinction between reference failures and implementation differences.

- Mode: `full-exact`
- Samples: 40
- Identical: 38 (95.0%)
- Different or failed: 2

| Sample | Result | Diffs | Seconds | Details |
|---|---:|---:|---:|---|
| `039a6336d0802a2255669e6867a5679c7eb83313dbc61fb1c7232147379bd304.exe_` | ok | 0 | 0.2 |  |
| `0831bb382211a67c57a392955138808526aa15e55531091841706aae2cb89613.exe_` | ok | 0 | 0.2 |  |
| `0953cc3b77ed2974b09e3a00708f88de931d681e2d0cb64afbaf714610beabe6.exe_` | ok | 0 | 0.2 |  |
| `2dae11cc5f86f5399b560b8837c26274b7e09431deed669b0844fef44e917915.exe_` | ok | 0 | 0.2 |  |
| `2fd45662e3d0ec0077ea2fa66b6378f0.exe_` | ok | 0 | 0.2 |  |
| `354a5de061795f8d961aae8e668ba9968083b1af09eeb9caed0111e7503974b5.exe_` | ok | 0 | 0.2 |  |
| `3f1f67e21469d9084696cc8ce75723405019ac085726ab9d51c97b797110ed1d.dll_` | ok | 0 | 0.1 |  |
| `6c8b0f234a239eb76c80b6e5b911720dfcd3738ff410375fbc65030c1f8fefe1.exe_` | ok | 0 | 0.2 |  |
| `6f6acca4d3696e08af9ed80f237f3542c362ebc2bcc9759bb64aa3f5c007320e.dll_` | ok | 0 | 0.2 |  |
| `749e7becf00fccc6dff324a83976dc0d.exe_` | ok | 0 | 0.2 |  |
| `805f79e57e4ce24b95a04541e4ea55dd2ce9ba314ab2c43491328204bc25d017.exe_` | ok | 0 | 0.2 |  |
| `8775ed26068788279726e08ff9665aab.exe_` | ok | 0 | 0.2 |  |
| `9df11356c5ac61d2aa7b5425e6322fc016b0ed5790dacb201396500b3eee03f7.exe_` | ok | 0 | 0.1 |  |
| `a301eadd2b665b696803e143dd4d657d71c56bbded2a3a1b96c5bcb83cc6796a.dll_` | ok | 0 | 0.2 |  |
| `aefae71bca4bbaa2c013ddf040d797628c8d3da7346108c12735239a86fdfa71.dll_` | ok | 0 | 0.1 |  |
| `b9f5bd514485fb06da39beff051b9fdc.exe_` | ok | 0 | 0.2 |  |
| `be619015f1d5fb13d3bcd48d1b0843759a5e040d8af3da50f2d8f55b5a680e02.dll_` | ok | 0 | 0.1 |  |
| `1c444ebeba24dcba8628b7dfe5fec7c6.exe_` | ok | 0 | 0.2 |  |
| `1ee70f829fa4f21b97fea53412383b4c83be1aaf8bab2f4b692549f8ceb4388f.dll_` | ok | 0 | 0.1 |  |
| `2c7d60f77812607dec5085973ff76cea.dll_` | ok | 0 | 0.2 |  |
| `387f15043f0198fd3a637b0758c2b6dde9ead795c3ed70803426fc355731b173.dll_` | ok | 0 | 0.3 |  |
| `692f7fd6d198e804d6af98eb9e390d61.exe_` | ok | 0 | 0.2 |  |
| `7f4ba9fc95b30baf8922a6933a4ff1c6a7fef41fae487bb31014c4963357770f.dll_` | ok | 0 | 0.3 |  |
| `dd9098ff91717f4906afe9dafdfa2f52.exe_` | ok | 0 | 0.2 |  |
| `e8ea789b860e8354b3ef5058bea7ea98.exe_` | ok | 0 | 0.2 |  |
| `e842958188274d5ffee7fbeffb803b2e.dll_` | ok | 0 | 0.1 |  |
| `hello-world.exe` | ok | 0 | 0.1 |  |
| `aaaaa.exe` | ok | 0 | 0.1 |  |
| `duplicate-stream.exe` | ok | 0 | 0.1 |  |
| `invalid-stream-name.exe` | diff | 1 | 0.0 | error: capa-x-cli failed on <repo>/target/full-validation/upstream/tests/data/dotnet/dnfile-testfiles/invalid-streams/invalid-stream-name.exe:
error: extracting .NET features: blob |
| `unknown-stream.exe` | diff | 1 | 0.0 | error: capa-x-cli failed on <repo>/target/full-validation/upstream/tests/data/dotnet/dnfile-testfiles/invalid-streams/unknown-stream.exe:
error: extracting .NET features: blob |
| `raw-binary.exe` | ok | 0 | 0.2 |  |
| `string-decoder.exe` | ok | 0 | 0.1 |  |
| `unpaired-surrogate.exe` | ok | 0 | 0.2 |  |
| `EmptyClass_amd64.exe` | ok | 0 | 0.1 |  |
| `EmptyClass_x86.exe` | ok | 0 | 0.1 |  |
| `EmptyClass_amd64.dll` | ok | 0 | 0.2 |  |
| `EmptyClass_x86.dll` | ok | 0 | 0.2 |  |
| `ModuleCode_amd64.exe` | ok | 0 | 0.2 |  |
| `ModuleCode_x86.exe` | ok | 0 | 0.2 |  |
