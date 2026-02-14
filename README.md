# netdumper

A .NET assembly dumper for Windows that extracts assemblies from running processes using the CLR Data Access Component (DAC).

## Features

- **DAC-based extraction** - Uses the CLR's debugging interface (`ISOSDacInterface`) to enumerate and dump all loaded assemblies
- **Anti-anti-dump** - Handles protected assemblies with corrupted PE headers or metadata:
  - Reconstructs corrupted PE headers from memory regions
  - Repairs BSJB metadata signatures and stream headers
  - Falls back to DAC metadata when PE metadata is destroyed
- **PE layout conversion** - Properly converts CLR's in-memory PE layout back to valid file layout
- **Machine type fix** - Corrects PE32+ headers with i386 machine type (CLR's AnyCPU quirk)
- **Smart naming** - Extracts names from Assembly table → Module table → file path
- **IL body recovery** - Recovers JIT'd method IL bodies via `GetILForModule`

## Usage

```
netdumper <COMMAND>

Commands:
  list      List running .NET processes
  enum      Enumerate assemblies from a process (read-only)
  dump      Dump assemblies from a process to disk
  diagnose  Diagnose .NET detection issues for a process
  analyze   Analyze a dumped assembly's metadata
```

### Examples

```bash
# List all .NET processes
netdumper list

# Enumerate assemblies (no dumping)
netdumper enum --name "MyApp"
netdumper enum --pid 1234

# Dump all assemblies to disk
netdumper dump --name "MyApp"
netdumper dump --pid 1234 --output ./dumped

# Diagnose detection issues
netdumper diagnose --pid 1234

# Analyze a dumped assembly
netdumper analyze ./dumped/MyAssembly.dll
```

## Building

Requires Rust nightly (edition 2024) and Windows.

```bash
cargo build --release
```

Binary: `target/release/netdumper.exe`

## How It Works

netdumper uses the CLR Data Access Component (DAC) to:

1. **Enumerate AppDomains** - Gets all application domains in the target process
2. **Enumerate Assemblies** - Lists all assemblies loaded in each AppDomain  
3. **Read Metadata** - Gets `metadataStart` and `metadataSize` directly from CLR internals
4. **Recover IL Bodies** - Uses `GetILForModule` to get method body addresses
5. **Reconstruct PE** - Converts memory layout to file layout with valid headers

### Why DAC?

- Knows about ALL assemblies the CLR has loaded
- Metadata addresses come from CLR internals, not PE parsing
- Works even when PE headers are completely destroyed
- Identifies dynamic/Reflection.Emit assemblies (which have no PE file)

### Anti-Anti-Dump

When assemblies have corrupted headers (packers/protectors), netdumper:

1. Detects corrupted MZ/PE signatures → reconstructs from memory regions
2. Detects zeroed BSJB signature → scans for #~ stream pattern
3. Rebuilds metadata stream headers (#~, #Strings, #US, #GUID, #Blob)
4. Falls back to DAC's metadata address when PE metadata is wrong
5. Fixes CLR's PE32+ with i386 machine type to AMD64

## Requirements

- Windows (uses Windows APIs and CLR DAC)
- Same architecture as target (x64 netdumper → x64 process)
- Administrator privileges may be required for some processes

## License

MIT
