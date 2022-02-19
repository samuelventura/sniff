defmodule Sniff.LeakTest do
  use ExUnit.Case
  alias Sniff.TTY

  # check leaks by comparing initial and final memory
  # this test wont detect a enif_alloc_binary leak!
  test "leak test" do
    tty0 = TTY.tty0()
    tty1 = TTY.tty1()
    parent = self()

    pid =
      spawn(fn ->
        receive do
          :ready -> send(parent, :ok)
        end

        receive do
          :start -> :ok
        end

        for _ <- 0..10 do
          {:ok, nid0} = Sniff.open(tty0, 115_200, "8N1")
          {:ok, nid1} = Sniff.open(tty1, 115_200, "8N1")

          for _ <- 0..10 do
            :ok = Sniff.write(nid0, "echo")
            wait(nid1, "echo")
          end

          :ok = Sniff.close(nid0)
          :ok = Sniff.close(nid1)
        end

        receive do
          :done -> send(parent, :ok)
        end

        receive do
          :ok -> :ok
        end
      end)

    send(pid, :ready)

    receive do
      :ok -> :ok
    end

    {:memory, mem0} = :erlang.process_info(pid, :memory)
    send(pid, :start)
    send(pid, :done)

    receive do
      :ok -> :ok
    end

    {:memory, mem1} = :erlang.process_info(pid, :memory)
    :erlang.garbage_collect(pid)
    :timer.sleep(200)
    {:memory, mem2} = :erlang.process_info(pid, :memory)
    IO.puts("mem start:#{mem0} end:#{mem1} final:#{mem2}")
    assert mem0 == mem2
  end

  defp wait(nid, bin), do: wait(nid, bin, "")

  defp wait(_nid, bin, bin), do: :ok

  defp wait(nid, bin, curr) do
    :timer.sleep(1)
    {:ok, part} = Sniff.read(nid)
    wait(nid, bin, curr <> part)
  end
end
