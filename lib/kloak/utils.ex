defmodule Kloak.Utils do
  @moduledoc """
  Utility module which offers some functionality for other modules.
  """

  # - Guard for validating the given value whether its an atom or path.
  defguardp is_key_or_path(value) when is_atom(value) or is_list(value)

  @doc """
  Fetches and retruns a setting fetched under the given key or path.
  When the setting was not found under the given key/path, the given default value is returned.
  According to `Application.compile_env/3` and `Application.compile_env!/2` it's possible to provide a key or a path of keys to fetch a setting.

  ## Examples
      iex> fetch_env(:keymaster, [:key_1, :key_2, :key_3])
      "value3"

      iex> fetch_env(:keymaster, [:key_1, :key_2, :key_3], "default")
      "default"

      iex> fetch_env(:keymaster, :other_key)
      "other_value"
  """
  @spec fetch_env(atom(), atom() | list(atom()), any()) :: any()
  def fetch_env(app, key_or_path, default \\ nil)
      when is_atom(app) and is_key_or_path(key_or_path) do
    case fetch_application_env(app, key_or_path) do
      {:ok, value} -> value
      :error -> default
    end
  end

  @doc """
  Fetches and retruns a setting fetched under the given key or path.
  When the setting was not found under the given key/path, an ArgumentError will be raised.
  According to `Application.compile_env/3` and `Application.compile_env!/2` it's possible to provide a key or a path of keys to fetch a setting.

  ## Examples
      iex> fetch_env!(:keymaster, [:key_1, :key_2, :key_3])
      "value3"

      iex> fetch_env!(:keymaster, [:key_1, :key_2, :key_3])
      ArgumentError

      iex> fetch_env(:keymaster, :other_key)
      "other_value"
  """
  @spec fetch_env!(atom(), atom() | list(atom())) :: any()
  def fetch_env!(app, key_or_path) when is_atom(app) and is_key_or_path(key_or_path) do
    case fetch_application_env(app, key_or_path) do
      {:ok, value} ->
        value

      :error ->
        raise ArgumentError,
              "could not fetch application environment #{inspect(key_or_path)} for application #{inspect(app)}!"
    end
  end

  ## -- Helper functions
  # - Fetch from application env
  @spec fetch_application_env(atom(), atom() | list(atom())) :: {:ok, any()} | :error
  defp fetch_application_env(app, key) when is_atom(key),
    do: fetch_application_env(app, key, [])

  defp fetch_application_env(app, [key | paths]) when is_atom(key),
    do: fetch_application_env(app, key, paths)

  defp fetch_application_env(app, key, path),
    do: traverse_application_env(Application.fetch_env(app, key), path)

  # - Traverses the given list
  @spec traverse_application_env({:ok, any()} | :error, list()) :: {:ok, any()} | :error
  defp traverse_application_env(return, []),
    do: return

  defp traverse_application_env(:error, _paths),
    do: :error

  defp traverse_application_env({:ok, value}, [key | keys]),
    do: traverse_application_env(Access.fetch(value, key), keys)
end
