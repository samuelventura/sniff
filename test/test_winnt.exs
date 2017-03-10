
defmodule Sniff.TTY do

  def name(id) do
    case id do
      0 -> "COM14"
      1 -> "COM16"
    end
  end

end
