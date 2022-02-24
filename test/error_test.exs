defmodule Sniff.ErrorTest do
  use ExUnit.Case
  alias Sniff.TTY

  test "error test" do
    tty0 = TTY.tty0()
    {:er, 'Argument 0 is not a binary'} = Sniff.open(nil, nil, nil)
    {:er, 'Invalid device'} = Sniff.open(bin(256), nil, nil)
    {:er, 'Argument 1 is not an integer'} = Sniff.open("", nil, nil)
    {:er, 'Invalid speed'} = Sniff.open(bin(250), 0, nil)
    {:er, 'Argument 2 is not a binary'} = Sniff.open("", 9600, nil)
    {:er, 'Invalid config'} = Sniff.open(bin(250), 9600, "22")
    {:er, 'Invalid config'} = Sniff.open(bin(250), 9600, "4444")

    case :os.type() do
      {:win32, :nt} ->
        {:er, 'CreateFile failed'} = Sniff.open(bin(250), 9600, "8N1")

      {:unix, :darwin} ->
        {:er, 'open failed'} = Sniff.open(bin(250), 9600, "8N1")

      {:unix, :linux} ->
        {:er, 'open failed'} = Sniff.open(bin(250), 9600, "8N1")
    end

    {:er, 'Invalid speed'} = Sniff.open(tty0, 9601, "8N1")
    {:er, 'Invalid config'} = Sniff.open(tty0, 9600, "8NX")
    {:ok, nid0} = Sniff.open(tty0, 115_200, "8N1")
    {:er, 'Argument 0 is not a resource'} = Sniff.read(nil)
    {:er, 'Argument 0 is not a resource'} = Sniff.write(nil, nil)
    {:er, 'Argument 1 is not a binary'} = Sniff.write(nid0, nil)
    {:er, 'Argument 0 is not a resource'} = Sniff.close(nil)
    :ok = Sniff.close(nid0)
    {:er, 'Already closed'} = Sniff.read(nid0)
    {:er, 'Already closed'} = Sniff.write(nid0, "")
    {:er, 'Already closed'} = Sniff.close(nid0)
    {:ok, nid0} = Sniff.open(tty0, 115_200, "8N1")
    :ok = Sniff.listen(nid0)
    {:er, 'Already listening'} = Sniff.listen(nid0)
    {:er, 'Already listening'} = Sniff.read(nid0)
    :ok = Sniff.close(nid0)
  end

  defp bin(size) do
    for _i <- 1..size, into: [] do
      "*"
    end
    |> :erlang.iolist_to_binary()
  end
end
