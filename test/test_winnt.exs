
defmodule Sniff.TTY do

  #Startech ICUSB2322F
  def name(id) do
    case id do
      0 -> "COM14"
      1 -> "COM16"
    end
  end

end
