defmodule Mix.Tasks.Compile.Nif do
  def run(_) do
    generate_env()
    case :os.type() do
      {:unix, :darwin} -> 0 = Mix.Shell.IO.cmd("make -f make.darwin")
      {:unix, :linux} -> 0 = Mix.Shell.IO.cmd("make -f make.linux")
      {:win32, :nt} -> 0 = Mix.Shell.IO.cmd("nmake /f make.winnt")
    end
    :ok
  end

  def clean() do
    generate_env()
    case :os.type() do
      {:unix, :darwin} -> 0 = Mix.Shell.IO.cmd("make -f make.darwin clean")
      {:unix, :linux} -> 0 = Mix.Shell.IO.cmd("make -f make.linux clean")
      {:win32, :nt} -> 0 = Mix.Shell.IO.cmd("nmake /f make.winnt clean")
    end
    :ok
  end

  defp generate_env() do
    build = Mix.Project.build_path()
    erts = Path.join([:code.root_dir(), 'erts-' ++ :erlang.system_info(:version)])
      |> fix_path_separator
    :ok = File.write "env.tmp", "BUILD_PATH=#{build}\nERTS_HOME=#{erts}"
  end

  defp fix_path_separator(path) do
    case :os.type() do
      {:win32, :nt} -> String.replace(path, "/", "\\")
      _ -> path
    end
  end
end

defmodule Sniff.Mixfile do
  use Mix.Project

  def project do
    [app: :sniff,
     version: "0.1.3",
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
    "Elixir Serial Port NIF"
  end

  defp package do
    [
     name: :sniff,
     files: ["priv/.gitignore", "lib", "src", "test", "mix.*", "make.*", "*.exs", "*.sh", "*.bat", "*.md", ".gitignore", "LICENSE"],
     maintainers: ["Samuel Ventura"],
     licenses: ["Apache 2.0"],
     links: %{"GitHub" => "https://github.com/samuelventura/sniff/"}]
  end

  defp aliases do
    [
    ]
  end
end
