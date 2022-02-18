defmodule Sniff.SpeedTest do
  use ExUnit.Case
  alias Sniff.TTY

  # macos {:er, 'tcsetattr failed'} ICUSB2328I
  # macos  {:er, 'Invalid speed'}
  test "valid speed test" do
    case :os.type() do
      # pending
      {:win32, :nt} ->
        test_speed(9600)

      {:unix, :darwin} ->
        test_speed(230_400)
        test_speed(115_200)
        test_speed(76800)
        test_speed(57600)
        test_speed(38400)
        test_speed(28800)
        test_speed(19200)
        test_speed(14400)
        test_speed(9600)
        test_speed(7200)
        test_speed(4800)
        test_speed(2400)
        test_speed(1800)
        test_speed(1200)
        test_speed(600)
        test_speed(300)
        test_speed(200)
        test_speed(150)
        test_speed(134)
        test_speed(110)
        test_speed(75)
        test_speed(50)

      {:unix, :linux} ->
        test_speed(4_000_000)
        test_speed(3_500_000)
        test_speed(3_000_000)
        test_speed(2_500_000)
        test_speed(2_000_000)
        test_speed(1_500_000)
        test_speed(1_152_000)
        test_speed(1_000_000)
        test_speed(921_600)
        test_speed(576_000)
        test_speed(500_000)
        test_speed(460_800)
        test_speed(230_400)
        test_speed(115_200)
        test_speed(57600)
        test_speed(38400)
        test_speed(19200)
        test_speed(9600)
        test_speed(4800)
        test_speed(2400)
        test_speed(1800)
        test_speed(1200)
        test_speed(600)
        test_speed(300)
        test_speed(200)
        test_speed(150)
        test_speed(134)
        test_speed(110)
        test_speed(75)
        test_speed(50)
    end
  end

  defp test_speed(speed) do
    tty0 = TTY.tty0()
    {:ok, nid0} = Sniff.open(tty0, speed, "8N1")
    :ok = Sniff.close(nid0)
  end
end
