defmodule Mix.Tasks.Compile.Nif do
  def run(_) do
    case :os.type() do
      {:unix, :darwin} -> 0 = Mix.Shell.IO.cmd("make -f make.darwin")
      {:unix, :linux} -> 0 = Mix.Shell.IO.cmd("make -f make.linux")
      {:win32, :nt} -> 0 = Mix.Shell.IO.cmd("build")
    end
    :ok
  end
end

defmodule Sniff.Mixfile do
  use Mix.Project

  def project do
    [app: :sniff,
     version: "0.1.0",
     elixir: "~> 1.3",
     compilers: [:nif | Mix.compilers],
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     aliases: aliases(),
     description: description(),
     package: package(),
     deps: deps()]
  end

  def application do
    [applications: []]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.12", only: :dev},
    ]
  end

  defp description do
    "Elixir Serial Port NIF."
  end

  defp package do
    [
     name: :sniff,
     files: ["lib", "src", "test", "mix.*", "make.*", "*.sh", "*.bat", "*.md", ".gitignore", "LICENSE"],
     maintainers: ["Samuel Ventura"],
     licenses: ["Apache 2.0"],
     links: %{"GitHub" => "https://github.com/samuelventura/sniff/"}]
  end

  defp aliases do
    [
    ]
  end
end
