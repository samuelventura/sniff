# sniff

Elixir Serial Port NIF

**Notice:** sniff focuses in the native interface to serial ports. For high level serial port access see [baud](https://github.com/samuelventura/baud).

## Installation and Usage

  1. Add `sniff` to your list of dependencies in `mix.exs`:

  ```elixir
  def deps do
    [{:sniff, "~> 0.1.2"}]
  end
  ```

## Roadmap

0.1.3

- [ ] Ensure farm.sh handles local.hex --force
- [ ] Document build server farm setup
- [ ] Cleanup windows compilation warnings

0.1.2

- [x] Empty priv is committed and included in hex package so that native libraries get copied to \_build when compiled as dependency

0.1.1

- [x] Tests pass on a clean Windows 10 VM (see build.bat)
- [x] Automatic test against Ubuntu 16 & Windows 10

0.1.0

- [x] Drop mac target until stable serial ports
- [x] Ubuntu 16.04 64 and Windows 10 Pro 64 support
- [x] Extract baud nif branch to its own repo

## Development

- Use clang-format atom package
- **build.bat** documents the required Windows build setup
- Testing requires two null modem serial ports configured in test/test_${OSNAME}.exs
- Test against the build server farm with:
```bash
./farm.sh remote
```

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
