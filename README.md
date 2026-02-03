# unrealengine-dump-helper

---

## Features

- Identifies and logs the following Unreal Engine functions:
  - `StaticFindObject`
  - `StaticLoadObject` (multiple patterns)
  - `FMemory::Malloc`
  - `UObject::ProcessEvent` (multiple patterns)

- Outputs the function name, virtual address, and offset relative to the image base.

- Includes debug output to track the plugin's operation.

---

## Installation

1. Copy the `FindFunctions` plugin script into the `<IDA Pro plugins directory>`.

2. Ensure that the required IDA Python libraries (`idaapi`, `idautils`, `idc`, `ida_search`) are available in your IDA Pro environment.

---

## Usage

1. Start IDA Pro and load your target binary.

2. Press `Alt-F` or access the plugin via the "Plugins" menu to execute the `FindFunctions` plugin.

3. The output will be displayed in the console log within IDA Pro, showing details of matched functions and their offsets.

---

## Output Example

```
[vmp-ue] Plugin run
[vmp-ue] Starting to find functions
[vmp-ue] Analyzing all functions...

[+] Found FMemory::Malloc : sub_2037C10 at 0x2037c10
[+] FMemory::Malloc Offset: 0x2037c10
[+] Found StaticFindObject : sub_20A0E4C at 0x20a0e4c
[+] StaticFindObject Offset: 0x20a0e4c
[+] Found function containg STLO: sub_2D16A2C at 0x2d16a2c
[+] StaticLoadObject Address: 0x2e555e4
[vmp-ue] Plugin terminated
```
