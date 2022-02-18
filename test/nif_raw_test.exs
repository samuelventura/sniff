defmodule Sniff.CrudTest do
  use ExUnit.Case
  alias Sniff.TTY

  test "all bytes are transmitted test" do
    tty0 = TTY.tty0()
    tty1 = TTY.tty1()
    {:ok, nid0} = Sniff.open(tty0, 115_200, "8N1")
    {:ok, nid1} = Sniff.open(tty1, 115_200, "8N1")

    all =
      Enum.reduce(0..255, [], fn i, list ->
        [<<i>> | list]
      end)
      |> Enum.reverse()
      |> :erlang.iolist_to_binary()

    # 115_200b/s % (8 + 2) = 11.52kB/s
    # 100ms ~> 1152B/s >> 256
    :ok = Sniff.write(nid0, all)
    :timer.sleep(100)
    {:ok, ^all} = Sniff.read(nid1)

    :ok = Sniff.close(nid0)
    :ok = Sniff.close(nid1)
  end
end
