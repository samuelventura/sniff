
defmodule Sniff.TTY do

  def name(id) do
    case id do
      0 -> "ttyS0"
      1 -> "ttyS5"
      2 -> "ttyS6"
      3 -> "ttyS7"
      4 -> "ttyS8"
      5 -> "ttyS9"
      6 -> "ttyS10"
      7 -> "ttyS11"
      8 -> "ttyS12"
    end
  end

end
