# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## About

`jaydb` is a Linux process debugger built following Sy Brand's [Building a Debugger](https://nostarch.com/building-a-debugger) book. It uses `ptrace` to control and inspect target processes. The original reference implementation is [sdb](https://github.com/TartanLlama/sdb).

## Build

Dependencies are managed via vcpkg (`libedit`, `catch2`, `fmt`). The build directory is `build/` at the repo root.

```sh
# Configure (from repo root)
cmake -B build

# Build everything
cmake --build build

# Build without tests
cmake -B build -DBUILD_TESTING=OFF && cmake --build build
```

## Testing

Tests use Catch2 and are in `test/tests.cpp`. Test target programs (compiled separately) live in `test/targets/`.

```sh
# Run all tests
cd build && ctest

# Run a specific test by name pattern (Catch2 filter)
./build/test/tests "[breakpoint]"
./build/test/tests "Can create breakpoint site"
```

## Architecture

The codebase is split into a library (`libjaydb`, built from `src/`) and a CLI frontend (`tools/jdb.cpp`).

**`jaydb::process`** (`include/libjdb/process.hpp`, `src/process.cpp`) — core class. Created only via `process::launch(path)` (forks and execs a new process under ptrace) or `process::attach(pid)`. Owns a `registers` instance and a `stoppoint_collection<breakpoint_site>`. Key operations: `resume()`, `wait_on_signal()`, `step_instruction()`, `create_breakpoint_site()`.

**`jaydb::registers`** (`include/libjdb/registers.hpp`, `src/registers.cpp`) — wraps `user_regs_struct` / `user_fpregs_struct` from `<sys/user.h>`. Reads and writes via `ptrace(PTRACE_GETREGS/SETREGS)`. Register metadata is defined in `include/libjdb/detail/registers.inc` and exposed through `g_register_infos` / `register_info_by_name` / `register_info_by_id`. The `read`/`write` methods use `registers::value`, a `std::variant` over all supported register types.

**`jaydb::breakpoint_site`** (`include/libjdb/breakpoint_site.hpp`, `src/breakpoint_site.cpp`) — software breakpoint at a `virt_addr`. Created only by `process::create_breakpoint_site()` (friend). `enable()` saves the original byte at the address and writes `0xCC` (INT3); `disable()` restores it.

**`jaydb::stoppoint_collection<T>`** (`include/libjdb/stoppoint_collection.hpp`) — header-only template container owning `unique_ptr<T>` stoppoints. Lookup by id or address; remove disables before erasing.

**`jaydb::virt_addr`** (`include/libjdb/types.hpp`) — strong typedef around `uint64_t` for virtual addresses, with arithmetic and comparison operators.

**CLI** (`tools/jdb.cpp`) — uses `libedit` for readline with history. Commands: `continue`, `step`, `register read/write`, `breakpoint set/list/enable/disable/delete`. All commands support prefix matching.

## Naming

The namespace and project name is `jaydb`. Public headers are under `include/libjdb/` but included as `<libjaydb/...>`. The library CMake target is `jaydb::libjaydb`.
