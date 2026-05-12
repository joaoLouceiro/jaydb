# jaydb

A Linux process debugger built by following Sy Brand's [Building a Debugger](https://nostarch.com/building-a-debugger) book. The original reference implementation is [sdb](https://github.com/TartanLlama/sdb).

## Pre-requisites

- CMake 3.19+
- A C++17-compatible compiler (GCC or Clang)
- [vcpkg](https://vcpkg.io) with the following packages: `libedit`, `fmt`, `catch2`
- `pkg-config`

## Build

```sh
cmake -B build
cmake --build build
```

To build without tests:

```sh
cmake -B build -DBUILD_TESTING=OFF
cmake --build build
```

## Testing

```sh
cd build && ctest
```

To run a specific subset of tests using Catch2 tag or name filters:

```sh
./build/test/tests "[breakpoint]"
./build/test/tests "Can create breakpoint site"
```
