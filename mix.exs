defmodule ExAwsSignature_2.Mixfile do
  use Mix.Project

  def project do
    [ app: :ex_aws_signature_2,
      version: "0.0.1",
      elixir: "~> 1.0.4",
      deps: deps ]
  end

  # Configuration for the OTP application
  def application do
    [applications: [:logger]]
  end

  # Returns the list of dependencies in the format:
  # { :foobar, git: "https://github.com/elixir-lang/foobar.git", tag: "0.1" }
  #
  # To specify particular versions, regardless of the tag, do:
  # { :barbat, "~> 0.1", github: "elixir-lang/barbat" }
  defp deps do
    [
     {:timex, github: "bitwalker/timex"},
     {:erlsha2, github: "vinoski/erlsha2"},
    ]
  end
end
