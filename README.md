# netdumper

A .NET assembly dumper for Windows that extracts assemblies from running processes using the CLR Data Access Component (DAC).

## Features

- **DAC-based enumeration** - Uses the CLR's debugging interface to enumerate all loaded assemblies, including dynamic/Reflection.Emit assemblies
- **Anti-anti-dump** - Handles protected assemblies with corrupted PE headers or metadata:
  - Reconstructs corrupted PE headers from memory regions
  - Rebuilds BSJB metadata signatures and stream headers
  - Falls back to DAC metadata when PE metadata is corrupted
- **Automatic name extraction** - Extracts assembly names from .NET metadata (Assembly or Module table)
- **IL body recovery** - Recovers method IL bodies using DAC's `GetILForModule`
- **Memory-to-file layout conversion** - Properly converts memory-mapped PE layout to file layout

## Usage

```
netdumper <COMMAND>

Commands:
  list      List running .NET processes
  enum      Enumerate assemblies from a process (read-only, no dumping)
  dump      Dump assemblies from a process to disk
  diagnose  Diagnose why .NET detection might be failing for a process
  analyze   Analyze a dumped assembly file to diagnose metadata issues
```

### Examples

List .NET processes:

```
netdumper list
```

Enumerate assemblies in a process:

```
netdumper enum --pid 1234
netdumper enum --name "MyApp.exe"
```

Dump assemblies to disk:

```
netdumper dump --pid 1234
netdumper dump --name "MyApp" --output ./dumped
```

Diagnose a process:

```
netdumper diagnose --pid 1234
```

Analyze a dumped assembly:

```
netdumper analyze ./dumped/MyAssembly.dll
```

## Building

Requires Rust (edition 2024) and Windows.

```
cargo build --release
```

The binary will be at `target/release/netdumper.exe`.

## How It Works

netdumper uses the CLR Data Access Component (DAC) via `ISOSDacInterface` to:

1. **Enumerate AppDomains** - Gets all application domains in the target process
2. **Enumerate Assemblies** - Lists all assemblies loaded in each AppDomain
3. **Get Metadata** - Reads `metadataStart` and `metadataSize` directly from CLR internals
4. **Get IL Bodies** - Uses `GetILForModule` to recover method bodies

This approach is more reliable than PE parsing alone because:

- DAC knows about all assemblies the CLR has loaded
- Metadata addresses come directly from the CLR, bypassing corrupted PE headers
- Works with dynamic assemblies that have no backing PE file

### Anti-Anti-Dump

When assemblies have corrupted headers (common with packers/protectors), netdumper:

1. Detects corrupted MZ/PE signatures and reconstructs headers from memory regions
2. Scans for #~ stream pattern when BSJB signature is zeroed
3. Rebuilds metadata stream headers (#~, #Strings, #US, #GUID, #Blob)
4. Uses DAC's metadata address as fallback when PE metadata location is wrong

## Requirements

- Windows (uses Windows APIs and CLR DAC)
- Target process must be same architecture (x64 netdumper for x64 processes)
- Administrator privileges may be required for some processes

## License

MIT
