defmodule Sniff.Mixfile do
  use Mix.Project

  def project do
    [
      app: :sniff,
      version: "0.1.8",
      elixir: "~> 1.3",
      make_clean: ["clean"],
      compilers: [:elixir_make | Mix.compilers()],
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  def application do
    [applications: []]
  end

  defp deps do
    [
      {:elixir_make, "~> 0.4", runtime: false},
      {:ex_doc, "~> 0.28", only: :dev}
    ]
  end

  defp description do
    "Elixir Serial Port NIF"
  end

  defp package do
    [
      name: :sniff,
      files: [
        "priv/.gitignore",
        "lib",
        "src",
        "test",
        "mix.*",
        "Makefile.*",
        "*.exs",
        "*.sh",
        "*.bat",
        "*.md",
        ".gitignore",
        "LICENSE"
      ],
      maintainers: ["Samuel Ventura"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/samuelventura/sniff/"}
    ]
  end

  defp aliases do
    []
  end
end
