# sniff

Elixir Serial Port NIF

**Notice:** sniff focuses in the native interface to serial ports. For higher level serial port access see [baud](https://github.com/samuelventura/baud).

## Installation

  Add `sniff` to your list of dependencies in `mix.exs`:

  ```elixir
  def deps do
    [{:sniff, "~> 0.1.7"}]
  end
  ```

## Usage

```elixir
#this echo sample requires a loopback plug
#supported config combinations {8,7}{N,E,O}{1,2}
iex(1)> {:ok, nid} = Sniff.open("/dev/ttyUSB0", 9600, "8N1")
{:ok, #Reference<0.83505167.3498704899.238160>}
iex(2)> Sniff.write(nid, "hello")
:ok
iex(3)> Sniff.read(nid)
{:ok, "hello"}
iex(4)> Sniff.close(nid)
:ok
```

## Test

```bash
# test with socat ttys
./test.sh
# test with custom ttys (null modem)
export TTY0="/dev/ttyUSB0"
export TTY1="/dev/ttyUSB1"
mix test
#in Windows
#requires COM98/COM99 com0com ports
test.bat
```

## Development

### Windows

Install `Visual C++ 2015 Build Tools` by one of the following methods:
- Download and install [visualcppbuildtools_full.exe](http://landinghub.visualstudio.com/visual-cpp-build-tools)
- With [Chocolatey](https://chocolatey.org/) `choco install VisualCppBuildTools`.

From the Windows run command launch `cmd /K c:\Users\samuel\Desktop\sniff\setenv.bat` adjusting your code location accordingly.

### Ubuntu

Give yourself access to serial ports with `sudo gpasswd -s samuel dialout`. Follow the official Elixir installation instructions and install `build-essential erlang-dev` as well.

### MacOS

Give yourself access to serial ports with `sudo dseditgroup -o edit -a samuel -t user wheel`.

## Roadmap

Future

- [ ] Binary distro to avoid devenv setup
- [ ] Cleanup windows compilation warnings

0.1.8

- [x] Support {8,7}{N,E,O}{1,2} configs

0.1.7

- [x] Auto close monitor and test
- [x] Migrated to elixir_make

0.1.6

- [x] Fixed raw mode to avoid byte 15 swallow in macos
- [x] Testing with fake socat ttys
- [x] Requires full posix serial port path
- [x] Pass test serial port thru environment variables

0.1.5

- [x] Added O_NONBLOCK for MacOS file open.
- [x] Tests confirmed to pass on linux.
- [x] Upgraded ex_doc to compile with latest elixir
- [x] Test serial port names detection on unixes
- [x] Fixed binary leak when serial_read fails
- [x] Separated darwin and linux baudrate files

0.1.4

- [x] Handle spaces in Windows build path

0.1.3

- [x] Document Windows dependencies
- [x] BAT to launch windows dev environment
    - A bat to call env.bat and cd back to code folder is provided
    - must be executed from Windows run command (no double click)
- [x] Ensure native library can be loaded on first compile
    - First deps.get && compile works fine
    - Second compile works fine
    - clean && compile fails to load NIF library
- [x] Ensure native library can be loaded from IEX
  - Tested on OSXElCapitan/Ubuntu16.10/Windows10
- [x] Ensure native library can be loaded when used as dependency from IEX
  - Tested on OSXElCapitan/Ubuntu16.10/Windows10
- [x] Pass the ERTS_HOME to unix makefiles
    - Tested on OSXElCapitan/Ubuntu16.10/Windows10

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

- Bypass the 0.1s minimum granularity on posix systems
- Higher baud rates support for posix and win32
- DTR/RTS control and CTS/DSR monitoring
- Unit test 8N1 7E1 7O1 and baud rate setup against a confirmed gauge
- Posix async and Windows overlapped
- _CRT_SECURE_NO_WARNINGS and strncpy_s suggestion in Windows
- Buffer discarding

## References

- https://www.cmrr.umn.edu/~strupp/serial.html
