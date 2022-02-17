defmodule Sniff.KillTest do
  use ExUnit.Case
  alias Sniff.TTY

  # check resource is auto closed on process exit
  # linux allows to open same port multiple times
  # this test is doing nothing
  test "kill test" do
    tty0 = TTY.tty0()

    pid =
      spawn(fn ->
        {:ok, _} = Sniff.open(tty0, 115_200, "8N1")

        receive do
          pid -> send(pid, :ok)
        end
      end)

    send(pid, self())
    assert_receive :ok, 800
    :timer.sleep(200)
    {:ok, nid0} = Sniff.open(tty0, 115_200, "8N1")
    :ok = Sniff.close(nid0)
  end
end
