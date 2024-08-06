defmodule Kloak.MixProject do
  use Mix.Project

  def project do
    [
      app: :kloak,
      version: "0.1.0",
      elixir: "~> 1.15",
      name: "kloak",
      source_url: "https://github.com/railsmechanic/kloak",
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :oauth2]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:plug, "~> 1.16"},
      {:b58, "~> 1.0.3"},
      {:jason, "~> 1.4.3"},
      {:oauth2, "~> 2.1.0"},
      {:ex_doc, "~> 0.34.1", only: :dev, runtime: false},
      {:earmark, "~> 1.4.46", only: [:dev]}
    ]
  end

  defp description do
    "Library for interacting with a Keycloak authorization server"
  end

  defp package do
    [
      maintainers: ["Matthias Kalb"],
      licenses: ["MIT"],
      links: %{"Github" => "https://github.com/railsmechanic/kloak"}
    ]
  end

  defp docs() do
    [
      main: "readme",
      extras: ["README.md"],
      skip_undefined_reference_warnings_on: ["readme", "README.md"]
    ]
  end
end
