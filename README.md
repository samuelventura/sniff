# sniff

Elixir Serial Port NIF.

## Installation and Usage

  1. Add `sniff` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:sniff, "~> 0.1.0"}]
    end
    ```

  **build.bat** documents the required Windows build tools.

## Roadmap

0.1.0

- [x] Drop mac target until stable serial ports.
- [x] Ubuntu 16.04 64 and Windows 10 Pro 64 support
- [x] Extract baud nif branch to its own repo
