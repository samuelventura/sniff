defmodule Sniff.SpeedTest do
  use ExUnit.Case
  alias Sniff.TTY

  test "valid speed test" do
    case :os.type() do
      {:win32, :nt} -> #pending
        test_speed 9600
      {:unix, :darwin} -> #pending
        test_speed 230400
        test_speed 115200
        test_speed 76800
        test_speed 57600
        test_speed 38400
        test_speed 28800
        test_speed 19200
        test_speed 14400
        test_speed 9600
        test_speed 7200
        test_speed 4800
        test_speed 2400
        test_speed 1800
        test_speed 1200
        test_speed 600
        test_speed 300
        test_speed 200
        #test_speed 150
        #test_speed 134
        #test_speed 110
        #test_speed 75
        #test_speed 50
        #{:er, 'tcsetattr failed'} ICUSB2328I
      {:unix, :linux} -> #passes
        test_speed 4000000
        test_speed 3500000
        test_speed 3000000
        test_speed 2500000
        test_speed 2000000
        test_speed 1500000
        test_speed 1152000
        test_speed 1000000
        test_speed 921600
        test_speed 576000
        test_speed 500000
        test_speed 460800
        test_speed 230400
        test_speed 115200
        test_speed 57600
        test_speed 38400
        test_speed 19200
        test_speed 9600
        test_speed 4800
        test_speed 2400
        test_speed 1800
        test_speed 1200
        test_speed 600
        test_speed 300
        test_speed 200
        test_speed 150
        test_speed 134
        test_speed 110
        test_speed 75
        test_speed 50
      end
  end
  
  defp test_speed(speed) do
    #IO.inspect {"test_speed", speed}
    tty0 = TTY.tty0
    {:ok, nid0} = Sniff.open tty0, speed, "8N1"
    :ok = Sniff.close nid0
  end

end
