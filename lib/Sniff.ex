defmodule Sniff do

  @compile {:autoload, false}
  @on_load :init

  def init() do
    nif = case :os.type() do
      {:unix, :darwin} -> :code.priv_dir(:sniff) ++ '/sniff_darwin'
      {:unix, :linux} -> :code.priv_dir(:sniff) ++ '/sniff_linux'
      {:win32, :nt} -> :code.priv_dir(:sniff) ++ '/sniff_winnt'
    end
    :erlang.load_nif(nif, 0)
  end

  def open(_device, _speed, _config) do
    "NIF library not loaded"
  end

  def read(_nid) do
    "NIF library not loaded"
  end

  def write(_nid, _data) do
    "NIF library not loaded"
  end

  def close(_nid) do
    "NIF library not loaded"
  end

end
