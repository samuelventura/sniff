defmodule Sniff.CrudTest do
  use ExUnit.Case
  alias Sniff.TTY

  test "crud test" do
    tty0 = TTY.name 1
    tty1 = TTY.name 2
    {:ok, nid0} = Sniff.open tty0, 115200, "8N1"
    {:ok, nid1} = Sniff.open tty1, 115200, "8N1"
    :ok = Sniff.write nid0, "echo"
    :timer.sleep 100
    {:ok, "echo"} = Sniff.read nid1
    :ok = Sniff.close nid0
    :ok = Sniff.close nid1
  end

end
