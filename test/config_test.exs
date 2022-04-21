defmodule Sniff.ConfigTest do
  use ExUnit.Case
  alias Sniff.TTY

  test "valid config test" do
    test_config("8N1")
    test_config("8N2")
    test_config("8E1")
    test_config("8E2")
    test_config("8O1")
    test_config("8O2")
    test_config("7N1")
    test_config("7N2")
    test_config("7E1")
    test_config("7E2")
    test_config("7O1")
    test_config("7O2")
  end

  defp test_config(config) do
    tty0 = TTY.tty0()
    {:ok, nid0} = Sniff.open(tty0, 9600, config)
    :ok = Sniff.close(nid0)
  end
end
