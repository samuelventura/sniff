
defmodule Sniff.TTY do

  #StarTech PEX8S952
  def name(id) do
    case id do
      0 -> "ttyUSB0"
      1 -> "ttyUSB1"
    end
  end

end
