defmodule Sniff do
  @moduledoc """
  Elixir Serial Port NIF.

  ```elixir
  #this echo sample requires a loopback plug
  iex(1)> {:ok, nid} = Sniff.open("/dev/ttyUSB0", 9600, "8N1")
  {:ok, #Reference<0.83505167.3498704899.238160>}
  iex(2)> Sniff.write(nid, "hello")
  :ok
  iex(3)> Sniff.read(nid)
  {:ok, "hello"}
  iex(4)> Sniff.close(nid)
  :ok
  ```

  The Serial Port is auto closed if its owner process exits.
  """

  @compile {:autoload, false}
  @on_load :init

  @doc false
  def init() do
    nif =
      case :os.type() do
        {:unix, :darwin} -> :code.priv_dir(:sniff) ++ '/sniff_darwin'
        {:unix, :linux} -> :code.priv_dir(:sniff) ++ '/sniff_linux'
        {:win32, :nt} -> :code.priv_dir(:sniff) ++ '/sniff_winnt'
      end

    :erlang.load_nif(nif, 0)
  end

  @doc """
    Opens the Serial Port.

    Returns `{:ok, nid}` | `{:er, reason}`.
  """
  def open(_device, _speed, _config) do
    :erlang.nif_error("NIF library not loaded")
  end

  @doc """
    Reads from the Serial Port (non blocking).

    Returns `{:ok, data}` | `{:er, reason}`.
  """
  def read(_nid) do
    :erlang.nif_error("NIF library not loaded")
  end

  @doc """
    Writes to the Serial Port.

    Returns `:ok` | `{:er, reason}`.
  """
  def write(_nid, _data) do
    :erlang.nif_error("NIF library not loaded")
  end

  @doc """
    Setups async Serial Port input. Sends a `{:data, data}` message to owner process on new input.

    Returns `:ok` | `{:er, reason}`.
  """
  def listen(_nid, _mid) do
    :erlang.nif_error("NIF library not loaded")
  end

  def listen(nid) do
    listen(nid, nid)
  end

  @doc """
    Closes the Serial Port.

    Returns `:ok` | `{:er, reason}`.
  """
  def close(_nid) do
    :erlang.nif_error("NIF library not loaded")
  end
end
