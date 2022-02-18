defmodule Sniff.KillTest do
  use ExUnit.Case
  alias Sniff.TTY

  # check resource is auto closed on process exit
  test "auto close on process exit test" do
    tty0 = TTY.tty0()
    self = self()

    pid =
      spawn(fn ->
        {:ok, sniff} = Sniff.open(tty0, 115_200, "8N1")
        send(self, sniff)
      end)

    ref = :erlang.monitor(:process, pid)
    assert_receive sniff, 400
    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 800
    # usb adapters may need a delay to reopen
    :timer.sleep(200)
    {:er, _} = Sniff.read(sniff)
    {:er, _} = Sniff.close(sniff)
    # check it is still usable
    {:ok, nid0} = Sniff.open(tty0, 115_200, "8N1")
    :ok = Sniff.close(nid0)
  end
end
