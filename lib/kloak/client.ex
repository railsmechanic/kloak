defmodule Kloak.Client do
  @moduledoc """
  Wrapper for building a properly configured `OAuth2.Client` which can be used with Keycloak.

  ## Configuration
    ```elxir
    config :kloak,
      site: <KEYCLOAK_SITE_URL>
      realm: <KEYCLOAK_REALM>
      client_id: <KEYCLOAK_CLIENT_ID>
      client_secret: <KEYCLOAK_CLIENT_SECRET>
    ```
  """

  @doc """
  Build a properly preconfigured `OAuth2.Client` for communicating with Keycloak.

  ## Examples
      iex> new()
      {:ok, %OAuth2.Client{}}

      iex> new()
      {:error, "Building the client failed due to an invalid configuration"}

      iex> new()
      {:error, "Building the client failed due to an error loading the configuration"}

      iex> new(nil)
      {:error, "Building the client failed due to invalid options"}
  """
  @spec new(keyword()) :: {:ok, OAuth2.Client.t()} | {:error, binary()}
  def new(opts \\ [])

  def new(opts) when is_list(opts) do
    case Keyword.merge(build_configuration!(), opts) do
      configuration when is_list(configuration) and length(configuration) > 0 ->
        {:ok, OAuth2.Client.new(configuration)}

      _invalid_configuration ->
        {:error, "Building the client failed due to an invalid configuration"}
    end
  rescue
    _environment_error ->
      {:error, "Building the client failed due to an error loading the configuration"}
  end

  def new(_opts),
    do: {:error, "Building the client failed due to invalid options"}

  @doc """
  Fetches the user information of the authenticated user from the Keycloak userinfo endpoint.
  The passed `OAuth2.Client` must be properly configured and authorized to perform this action.

  ## Examples
      iex> user_information(valid_client)
      {:ok, %{"given_name" => "John", ...}}

      iex> user_information(invalid_client)
      {:error, "Fetching user information from Keycloak failed with an error"}

      iex> user_information(invalid_client)
      {:error, "Fetching user information failed due to an error loading the configuration"}

      iex> user_information(nil)
      {:error, "Fetching user information failed due to an invalid OAuth client"}
  """
  @spec user_information(OAuth2.Client.t()) :: {:ok, map()} | {:error, binary()}
  def user_information(client)

  def user_information(%OAuth2.Client{} = client) do
    case OAuth2.Client.get(client, "/realms/#{keycloak_realm!()}/protocol/openid-connect/userinfo") do
      {:ok, %OAuth2.Response{status_code: 200, body: user_information}} when is_map(user_information) and map_size(user_information) > 0 ->
        {:ok, user_information}

      {:error, _message} ->
        {:error, "Fetching user information from Keycloak failed with an error"}
    end
  rescue
    _environment_error ->
      {:error, "Fetching user information failed due to an error loading the configuration"}
  end

  def user_information(_client),
    do: {:error, "Fetching user information failed due to an invalid OAuth client"}

  ## -- Helper functions
  # - Build the configuration for the `OAuth2.Client` which can be used with Keycloak.
  @spec build_configuration!() :: keyword()
  defp build_configuration!() do
    [
      strategy: OAuth2.Strategy.AuthCode,
      site: keycloak_site!(),
      realm: keycloak_realm!(),
      client_id: keycloak_client_id!(),
      client_secret: keycloak_client_secret!(),
      headers: [{"Accept", "application/json"}],
      authorize_url: "/realms/#{keycloak_realm!()}/protocol/openid-connect/auth",
      token_url: "/realms/#{keycloak_realm!()}/protocol/openid-connect/token",
      serializers: %{"application/json" => Jason}
    ]
  end

  ## -- Environment helper functions
  # - Fetch the keycloak `realm` configuration.
  @spec keycloak_realm! :: binary()
  defp keycloak_realm!,
    do: Kloak.Utils.fetch_env!(:kloak, [:realm])

  # - Fetch the keycloak `site` configuration.
  @spec keycloak_site! :: binary()
  defp keycloak_site!,
    do: Kloak.Utils.fetch_env!(:kloak, [:site])

  # - Fetch the keycloak `client_id` configuration.
  @spec keycloak_client_id! :: binary()
  defp keycloak_client_id!,
    do: Kloak.Utils.fetch_env!(:kloak, [:client_id])

  # - Fetch the keycloak `client_secret` configuration.
  @spec keycloak_client_secret! :: binary()
  defp keycloak_client_secret!,
    do: Kloak.Utils.fetch_env!(:kloak, [:client_secret])
end
