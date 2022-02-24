defmodule Sniff.ListenTest do
  use ExUnit.Case
  alias Sniff.TTY

  test "simple test after c code refactor" do
    tty0 = TTY.tty0()
    tty1 = TTY.tty1()
    {:ok, nid0} = Sniff.open(tty0, 115_200, "8N1")
    {:ok, nid1} = Sniff.open(tty1, 115_200, "8N1")

    self = self()
    :ok = Sniff.listen(nid0)
    Sniff.write(nid1, "1")
    assert_receive {:sniff, ^self, "1"}, 200
    Sniff.write(nid1, "1")
    assert_receive {:sniff, ^self, "1"}, 200

    :ok = Sniff.close(nid0)
    :ok = Sniff.close(nid1)

    :timer.sleep(200)
  end
end
