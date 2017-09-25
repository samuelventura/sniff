# sniff

Elixir Serial Port NIF

**Notice:** sniff focuses in the native interface to serial ports. For high level serial port access see [baud](https://github.com/samuelventura/baud).

## Installation and Usage

  1. Add `sniff` to your list of dependencies in `mix.exs`:

  ```elixir
  def deps do
    [{:sniff, "~> 0.1.3"}]
  end
  ```

## Development

  - Use clang-format atom package to format C code
  - Testing requires two null modem serial ports configured in test/test_${OSNAME}.exs
  - Test against the build server farm with:
  ```bash
  ./farm.sh remote
  ```

## Windows

Install `Visual C++ 2015 Build Tools` by one of the following methods:
- Download and install [visualcppbuildtools_full.exe](http://landinghub.visualstudio.com/visual-cpp-build-tools)
- Thru [Chocolatey](https://chocolatey.org/) `choco install VisualCppBuildTools`.

From the Windows run command exec `cmd /K c:\Users\samuel\Documents\github\sniff\setenv.bat` adjusting your code location accordingly.

## Roadmap

0.1.4

- [ ] Ensure farm.sh handles local.hex --force
- [ ] Document build server farm setup
- [ ] Cleanup windows compilation warnings
- [ ] Document Windows dependencies
- [ ] BAT to launch windows dev environment
- [ ] Pass the ERTS_HOME to unix makefiles
- [ ] Patch elixir_make to:
    - Allow using a different make file for each unix platform
    - Pass the ERTS_HOME to the makefile
    - Pass the MIX_ENV to the makefile

0.1.3

- [x] Ensure native library can be loaded on first compile
    - First deps.get && compile works fine
    - Second compile works fine
    - clean && compile fails to load NIF library
- [x] Ensure native library can be loaded from IEX
- [ ] Ensure native library can be loaded when used as dependency from IEX

0.1.2

- [x] Empty priv is committed and included in hex package so that native libraries get copied to `_build` when compiled as dependency

0.1.1

- [x] Tests pass on a clean Windows 10 VM (see build.bat)
- [x] Automatic test against Ubuntu 16 & Windows 10

0.1.0

- [x] Drop mac target until stable serial ports
- [x] Ubuntu 16.04 64 and Windows 10 Pro 64 support
- [x] Extract baud nif branch to its own repo

## Research

- Support udoo neo
- Support beaglebone black
- Support raspberry pi 3 B
- Bypass the 0.1s minimum granularity on posix systems
- Higher baud rates support for posix and win32
- DTR/RTS control and CTS/DSR monitoring
- Unit test 8N1 7E1 7O1 and baud rate setup against a confirmed gauge
- Posix async and Windows overlapped
- Buffer discarding
