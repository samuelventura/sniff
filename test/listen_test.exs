defmodule Sniff.ListenTest do
  use ExUnit.Case
  alias Sniff.TTY

  test "simple test after c code refactor" do
    tty0 = TTY.tty0()
    tty1 = TTY.tty1()
    {:ok, nid0} = Sniff.open(tty0, 115_200, "8N1")
    {:ok, nid1} = Sniff.open(tty1, 115_200, "8N1")

    IO.inspect("BEFORE LISTEN")
    :ok = Sniff.listen(nid0)
    IO.inspect("AFTER LISTEN")

    Sniff.write(nid1, "1")
    IO.inspect("AFTER WRITE")

    # assert_receive {:sniff, :data, "1"}, 200
    receive do
      {:sniff, :data, "1"} -> IO.inspect("GOT IT")
    after
      500 ->
        IO.inspect("TIMEOUT")
    end

    IO.inspect("AFTER RECEIVE")

    :ok = Sniff.close(nid0)
    :ok = Sniff.close(nid1)
    IO.inspect("AFTER CLOSE")

    :timer.sleep(1000)
  end
end
