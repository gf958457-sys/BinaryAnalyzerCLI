# BinaryAnalyzerCLI

Production-oriented .NET 10 console application for static disassembly and first-pass triage of **PE / ELF / Raw** binaries, using either **Capstone** or **iced-x86** as an interchangeable disassembly backend, with function discovery, normalized semantic analysis, and an optional AI pass (OpenRouter) over the results.

*Build:* `0 errors` · *Tests:* `430/430` (Release, xUnit) · *Target:* `net10.0` · *Engines:* `Iced 1.21.0` + `Gee.External.Capstone 2.3.0` (native Capstone 4)

## ⚠️ Important, honest caveat about "Capstone 5"

You asked for Capstone Engine **5**. The best-maintained managed .NET binding,
[`Gee.External.Capstone`](https://www.nuget.org/packages/Gee.External.Capstone)
(v2.3.x, referenced in the `.csproj`), currently wraps the native **Capstone 4**
library — there is no mainstream managed wrapper for Capstone 5 published on
NuGet at the time of writing. I'm not going to pretend otherwise.

The code is architected so this is a non-issue going forward:
`CapstoneDisassemblerEngine` is fully isolated behind `IDisassemblerEngine`,
and all Capstone-specific API calls live in one file
(`Disassembler/Capstone/CapstoneDisassemblerEngine.cs`). If/when you want true
Capstone 5:

* **Option A (recommended, given your P/Invoke background):**
  P/Invoke directly against a native `capstone.dll` / `libcapstone.so` built
  from the Capstone 5 source tree. The public C ABI (`cs_open`, `cs_option`,
  `cs_disasm`, `cs_free`, etc.) is stable between major versions, so this is a
  contained, well-scoped change — swap the internals of
  `CapstoneDisassemblerEngine`, keep the `IDisassemblerEngine` contract.
* **Option B:** Track `Gee.External.Capstone` upstream and bump the package
  version once/if it ships a Capstone 5 build.

Native library probing is handled explicitly: framework-dependent builds probe
`runtimes/<RID>/native/capstone.dll` via `deps.json`, self-contained publish
places `capstone.dll` next to the exe. If the native is absent, the engine
fails **cleanly** with `CapstoneNativeLibraryException`:

```
Не найдена нативная библиотека capstone.dll — движок разбора Capstone недоступен.
Куда положить : рядом с BinaryAnalyzerCLI.exe
Где взять     : runtimes/win-x64/native/capstone.dll или пересоберите (dotnet build -c Release)
```

No partial `AnalysisResult` is produced — the `disassemble` command aborts with a red diagnostic (Ghidra-style philosophy: full correct result or honest failure).

Everything else (iced-x86 engine, PE/ELF parsing, exporters, AI integration, CLI) has no such caveat and is fully functional.

## Architecture

```
BinaryAnalyzerCLI/  (81 .cs files: 62 prod + 19 test)
  Core/
    Interfaces/       IDisassemblerEngine, IAIProvider, IBinaryParser, IExporter,
                      IInstructionProvider, IFunctionDiscovery,
                      IFunctionInstructionStatisticsService
    Models/           Architecture, BinaryFormat, InstructionInfo + InstructionSemantics,
                      OperandSemantics, NormalizedFlowControl, OperandKind/Access,
                      InstructionCategory, InstructionPrefixes, RegisterId,
                      BinaryFileInfo, AnalysisResult, FunctionInfo, FunctionSource,
                      FunctionInstructionStatistics, DecodingIdentity, RegionDescriptor,
                      ExecutableRegion, AppSettings, AiSettings, StringMatch, SuspiciousApiMatch
  Disassembler/
    Capstone/         CapstoneDisassemblerEngine + CapstoneSemanticAdapter
                      CapstoneNativeLibraryException (native-load diagnostics)
    Iced/             IcedDisassemblerEngine + IcedSemanticAdapter
    DisassemblerEngineFactory.cs  (Resolve + ResolveForArchitecture + ResolveTypeForArchitecture)
  Analysis/
    BinaryFormatDetector.cs   PE/ELF magic + machine-type detection
    PeAnalyzer.cs             PE header/section/import parsing
    ElfAnalyzer.cs            ELF32/64 header/section parsing (little/big endian)
    RawAnalyzer.cs            fallback for headerless/raw binaries
    OnDemandInstructionProvider.cs  streaming provider (ExecutableRegion[] + DecodingIdentity, O(1) retained)
    FunctionInstructionService.cs   on-demand re-decode of a function slice (256 KiB, deterministic replay)
    FunctionDiscoveryService.cs     entry-point + direct-call regex + prologue heuristics (push rbp / stp x29)
    FunctionBoundaryResolver.cs     group-by-region, EndAddress/EndByteAddress/InstructionCount, deterministic
    FunctionInstructionStatisticsService.cs  streaming statistics from normalized Semantics
    StaticAnalysisService.cs      orchestrates parse → regions → disassemble → estimator → provider → discovery
    StringExtractor.cs        ASCII + UTF-16LE
    SuspiciousApiScanner.cs   IOC / suspicious API signatures
  AI/
    OpenRouter/         OpenRouterProvider : IAIProvider
    AiAnalysisService.cs  bounded prompt context (4000 instr) from AnalysisResult
  Export/
    AssemblyExporter.cs  streaming ASM.txt writer
    HexExporter.cs        streaming hex.txt writer
  Config/
    SettingsManager.cs    loads/saves Settings.json + Ai.json
  CLI/
    Commands/            OpenCommand, SettingsCommand, DisassembleCommand,
                         ExportAsmCommand, ExportHexCommand, AiAnalyzeCommand,
                         FunctionsCommand, HelpCommand, ICommand
    AppSession.cs         current file / analysis state (single AnalysisResult)
    CommandRouter.cs       keyword → ICommand dispatch (longest match, try/catch)
    ConsoleUI.cs           colored output + in-place ProgressBar
  Tests/ (19 files, 430 tests)
    Helpers/StatisticsTestHelper.cs  deterministic single-function PE/ELF builders
    InstructionSemanticsTests.cs / Iced/Capstone/Arm/CrossEngine parity
    FunctionDiscoveryTests.cs (F1 byte-slicing, boundaries, retrieval)
    StatisticsBaselineTests.cs / FunctionInstructionSemanticStatisticsTests.cs
    StatisticsIntegrationTests.cs / StatisticsPerformanceTests.cs
    IdentityEngineResolutionTests.cs / CapstoneNativeFailureTests.cs
    + Elf/Pe/InstructionProvider/PreservedInvariants etc.
  Program.cs              DI container wiring + interactive REPL loop
  Settings.json / Ai.json  default config, copied to output on build
  docs/C3_GATE.md          final C.3 Statistics Migration gate document
```

### Full pipeline

```
Binary Open
     ↓ BinaryFormatDetector → PeAnalyzer / ElfAnalyzer / RawAnalyzer
BinaryFileInfo + ExecutableRegion[] (owned buffers)
     ↓ DisassemblerEngineFactory.ResolveForArchitecture → Iced / Capstone
OnDemandInstructionProvider(ExecutableRegion[] + DecodingIdentity{Engine,EffectiveArch,ChunkSize} + Count)
     ↓ DisassembleStreaming (256 KiB, resync, progress)
InstructionInfo + InstructionSemantics{IsValid, FlowControl, BranchTarget, Category, Prefixes, Op0..Op3}
     ↓ FunctionDiscovery (entry + call-target + prologue) → FunctionBoundaryResolver → FunctionInfo{Start,End,EndByte,Count}
AnalysisResult{FileInfo, Instructions:IInstructionProvider, EngineUsed(effective), Functions, EstimatedFunctionCount}
     ↓ FunctionInstructionService.GetInstructions(FunctionInfo) — fresh engine, 256 KiB, streaming to EndAddress
FunctionInstructionStatisticsService.ComputeStatistics — fully semantic:
  total++ always; if (!IsValid) skip flow/category/memory
  flow     → switch(FlowControl) Call/IndirectCall→Call, Uncond/IndirectBranch→Jump, ConditionalBranch→Cond, Return→Ret
  category → switch(Category) Arithmetic/Logical/Stack
  memory   → for k<OperandCount: IsMemory && Access!=None → hasMemory/isRead/isWrite → memOp/read/write/RW
  ByteSize = EndByteAddress-Start+1; Complexity = 1+ConditionalBranchCount
     ↓ FunctionInstructionStatistics{Total,Call,Jump,Cond,Ret,Branch,MemOp/R/W/RW,Arith,Logical,Stack,ByteSize,Complexity}
     ↓
CLI (FunctionsCommand FullText, 256 KiB replay) / Export (BytesHex/FullText) / AI (FullText excerpt)
```

Design points relevant to your stated requirements:

* **DI everywhere**: `Program.cs` wires every service through `Microsoft.Extensions.DependencyInjection`; commands, engines, parsers and exporters are all resolved from the container, not `new`'d ad-hoc.
* **Engine interchangeability + fallback:** both engines implement `IDisassemblerEngine` exactly; `DisassemblerEngineFactory` resolves the active one from `Settings.json`, with automatic fallback to Capstone for ARM/ARM64 since iced only covers x86/x64. The **effective** engine type (after fallback) is snapshotted into `DecodingIdentity`/`AnalysisResult.EngineUsed`, so on-demand replay always resolves the engine that actually decoded the bytes (S14 fix).
* **Streaming / memory:** `OnDemandInstructionProvider` retains only `ExecutableRegion[]` byte buffers + `DecodingIdentity`; `InstructionInfo` objects are transient. `DisassembleStreaming` uses `BufferedStream` (256 KiB) with overlap, and `FunctionInstructionService` re-decodes only the function's byte slice with the same chunk size — no `List<InstructionInfo>` is ever retained. Statistics stream once per function (`Time O(N)`, retained `O(1)`). Verified: per-iteration allocation ratio large/small 7.1× for 500× instructions (not retained list).
* **Normalized semantics:** Every decoded instruction carries `InstructionSemantics` (112 B inline value type, zero heap allocations per instruction, `IsValid`-first contract, `RegisterId` non-canonical per (Arch,Engine)). Adapters are the only place where `Iced.Intel.*` / `Gee.External.Capstone.*` types appear. Statistics, discovery, and future CFG/DataFlow consume semantics, never `Mnemonic`/`Operands` text. Text remains the single source for display/export/AI.
* **Determinism & parity:** `OnDemandInstructionProvider` replays identically; `CrossEngineSemanticParityTests` pins 62 x86 encodings and ARM smoke tests; `where.exe` Iced vs Capstone control-flow identical; `libCrossOff.so` (ARM32) and `GameAssembly.dll` (x64) validated on real functions.
* **Progress reporting**: `IProgress<double>` flows from the engine through `StaticAnalysisService` to `ConsoleUI.ProgressBar`, rendered in-place as `[████████░░] 80%`.
* **Exceptions**: parsers/engines catch and log malformed-input failures and degrade to best-effort metadata rather than crashing the session; the `CommandRouter` wraps every command execution so one bad command can't kill the interactive loop. Missing native Capstone is a typed clean failure (see caveat above).

## Requirements

* .NET 10 SDK
* Internet access on first build (NuGet restore) for: `Iced`, `Gee.External.Capstone`, `Microsoft.Extensions.*`

**Note on `System.CommandLine`**: it was intentionally left out. It's built for one-shot `myapp <verb> <options>` invocations, not the persistent `BinaryAnalyzerCLI>` REPL this spec calls for — using it would mean fighting its parser model rather than benefiting from it. The custom `CommandRouter` / `ICommand` pair in `CLI/` fills that role instead and is trivial to extend. If you'd rather standardize on it for the initial-argument case (`BinaryAnalyzerCLI.exe open malware.exe`) specifically, that's a clean, isolated addition in `Program.cs`.

## Install & build

```bash
cd BinaryAnalyzerCLI
dotnet restore
dotnet build -c Release
dotnet test -c Release   # 430/430
```

## Run

```bash
dotnet run -c Release
# or, after publish:
dotnet publish -c Release -o out
./out/BinaryAnalyzerCLI      # Linux/macOS
out\BinaryAnalyzerCLI.exe    # Windows
```

## First-run configuration

Edit `Ai.json` (copied next to the built exe) and set a real `ApiKey` before using `ai analys`:

```json
{
  "Provider": "OpenRouter",
  "ApiKey": "sk-or-v1-...",
  "Model": "anthropic/claude-sonnet-5",
  "Endpoint": "https://openrouter.ai/api/v1/chat/completions",
  "Temperature": 0.2,
  "MaxTokens": 4096
}
```

`Settings.json` controls the disassembler engine, export directory, output format and whether AI features are enabled; it's also editable live via the `settings` command.

## Usage example

```
BinaryAnalyzerCLI.exe open malware.exe

BinaryAnalyzerCLI> settings
[1] Disassembler engine : Iced  (Capstone 5 / iced-x86)
...
select> 1
[1] Capstone 5
[2] iced-x86
engine> 2

BinaryAnalyzerCLI> disassemble
Disassembling malware.exe using Iced engine...
Progress: [██████████████████████████████] 100%
Disassembly complete.
  Engine used:           Iced
  Instructions decoded:  184,213
  Estimated functions:   1,042
  Strings extracted:     3,881
  Suspicious API hits:   6
Suspicious API usage detected:
    - VirtualAlloc [MemoryAllocation]
    - CreateRemoteThread [ProcessInjection]
    - LoadLibraryA [DynamicLoading]
    ...

BinaryAnalyzerCLI> functions
Functions: 104
 #    Start Address      End Address        Instructions  Source             Confirmations
------------------------------------------------------------------------------------------
 1    0x140001300        0x140001327        26            entrypoint         1
 ...

BinaryAnalyzerCLI> export asm
Exported assembly listing to 'Exports/ASM.txt'.

BinaryAnalyzerCLI> export hex
Exported hex dump to 'Exports/hex.txt'.

BinaryAnalyzerCLI> ai analys
Entering AI analysis mode. Ask a question, or type 'back' to return.
BinaryAnalyzerCLI AI> Find potential vulnerabilities
Analyzing (this may take a few seconds)...

=== AI Analysis ===
...
```

## ASM.txt export format

```
00401000:
55
push rbp

00401001:
4889E5
mov rbp,rsp
```

## hex.txt export format

```
OFFSET    | BYTES                                           | ASCII
------------------------------------------------------------------------
00000000  | 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 | MZ..............
```

## Statistics (post-C.3 — fully semantic)

Per-function `FunctionInstructionStatistics` is now derived **only** from `InstructionInfo.Semantics` (no `Mnemonic`/`Operands` parsing):

* `TotalInstructions` — every yielded `InstructionInfo` (including `(bad)`)
* `CallCount` — `FlowControl.Call` + `IndirectCall` (covers `call rel32`, `call rax/[rax]`, ARM `bl`/`blr`)
* `JumpCount` — `UnconditionalBranch` + `IndirectBranch`
* `ConditionalBranchCount` — `ConditionalBranch` (covers `jcc`, `loop`/`jcxz`/`jecxz`/`jrcxz`, ARM `b.eq`/`cbz`/`tbnz`)
* `RetCount` — `Return` only (not `InterruptReturn`)
* `BranchCount` → `Jump + Conditional`
* `MemoryOperationCount` / `Read` / `Write` / `ReadWrite` — per-instruction `OperandKind.Memory && Access!=None` + `HasRead`/`HasWrite` (`ConditionalReadWrite` counts as both; `lea`/`nop [mem]` excluded via `Access.None`; `rep movsb` with 2 mem operands aggregated as 1 `ReadWrite`)
* `ArithmeticInstructionCount` / `LogicalInstructionCount` / `StackInstructionCount` — `InstructionCategory` (`GetX86` 22/29/12 entries, `GetArm`/`GetArm64` scoped; `cmp`/`adcx`/`shl`/`pushfq` now correctly counted)
* `ByteSize` — `EndByteAddress - StartAddress + 1`
* `ComplexityEstimate` → `1 + ConditionalBranchCount` (project-specific, not full CFG)

Validated on `where.exe`, `kernel32.dll`, `GameAssembly.dll`, `libCrossOff.so` (ARM32) with 62-encoding cross-engine parity.

## Testing

```bash
dotnet test -c Release
# 430 tests: PE/ELF/Raw parsing, streaming, multi-section, unknown-arch,
# function discovery/boundaries/retrieval, semantic adapters (Iced/Capstone/ARM),
# cross-engine parity, statistics baseline (23) + semantic (35) + integration (9)
# + performance smoke (3), identity resolution, native-load failure
```

Performance smoke (`Tests/StatisticsPerformanceTests.cs`) asserts hot path contains no `ToLowerInvariant`/`Contains('[')`/`ToList` and that large/small allocation ratio stays bounded (streaming, not retained list).

## Extending

* **New disassembler engine**: implement `IDisassemblerEngine`, register it in `Program.cs`, add a branch in `DisassemblerEngineFactory`.
* **New AI provider** (OpenAI, local model, ...): implement `IAIProvider`, swap the `AddHttpClient<IAIProvider, ...>()` registration in `Program.cs`.
* **New export format**: implement `IExporter`, register as `AddSingleton`, add a CLI command that calls it (mirror `ExportAsmCommand`).
* **New container format** (Mach-O, .NET/IL2CPP metadata, ...): implement `IBinaryParser`, register alongside `PeAnalyzer`/`ElfAnalyzer`.
* **New statistics**: add a `Category` value to `InstructionCategoryTable` and a counter in `FunctionInstructionStatisticsService` that reads it — no string work needed.
