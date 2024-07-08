defmodule Kloak do
  @moduledoc """
  This module is as a simple wrapper around `OAuth2`, which helps building a valid configuration for authorizing with a [Keycloak](http://www.keycloak.org/) server.

  ## Examples

  #### Phoenix controller
      @doc "Login controller action which redirects to Keycloak for authentication."
      def login(conn, _) do
        with {:ok, client} <- Kloak.Client.new(), {:ok, nonce} <- generate_nonce(),
             {:ok, redirect_url} <- Kloak.authorization_url(client, scope: "openid", state: nonce, redirect_uri: url(~p"/auth/callback")) do
          conn
          |> put_oidc_state(nonce)
          |> redirect(external: redirect_url)
        end
      end

      @doc "Callback controller action which is called when a users is redirected from Keycloak."
      def callback(conn, %{"code" => code, "state" => state}) do
        with {:ok, true} <- verify_oidc_state(conn, state),
            {:ok, client} <- Kloak.Client.new(),
            {:ok, token} <- Kloak.get_token(client, code: code, redirect_uri: url(~p"/auth/callback")),
            {:ok, client} <- Kloak.Client.new(token: token),
            {:ok, user_information} <- Kloak.user_information(client) do
          # Do something with the user information
          IO.inspect(user_information)

          # Authentication was successful
          conn
          |> put_session(:token, token)
          |> put_flash(:info, gettext("You have successfully logged in."))
          |> redirect(to: ~p"/dashboard")
        end
      end
  """

  @doc """
  Fetches the user information of the authenticated user from the Keycloak userinfo endpoint.
  The passed `OAuth2.Client` must be properly configured and authorized to perform this action.

  ## Examples
      iex> user_information(valid_client)
      {:ok, %{"given_name" => "John", ...}}

      iex> user_information(invalid_client)
      {:error, "Retriving user information from Keycloak failed with an error"}

      iex> user_information(invalid_client)
      {:error, "Retriving user information failed due to an invalid realm configuration"}
  """
  @spec user_information(OAuth2.Client.t()) :: {:ok, map()} | {:error, binary()}
  defdelegate user_information(client), to: Kloak.Client

  @doc """
  Build the autorization URL, which is required in the authentication flow.
  This built URL is used for redirecting to Keycloak.

  ## Examples
      iex> authorize_url(%OAuth2.Client{...})
      {:ok, "https://localhost:4000/..."}

      iex> authorize_url(%OAuth2.Client{...})
      {:error, "Building the authorization URL failed with an invalid URL"}

      iex> authorize_url(%OAuth2.Client{...})
      {:error, "Building the authorization URL failed with an unknown error"}
  """
  @spec authorize_url(OAuth2.Client.t(), keyword()) :: {:ok, binary()} | {:error, binary()}
  def authorize_url(%OAuth2.Client{} = client, params \\ []) when is_list(params) do
    case OAuth2.Client.authorize_url!(client, params) do
      authorize_url when is_binary(authorize_url) and byte_size(authorize_url) > 0 ->
        {:ok, authorize_url}

      _invalid_authorize_url ->
        {:error, "Building the authorization URL failed with an invalid URL"}
    end
  rescue
    _unknown_error ->
      {:error, "Building the authorization URL failed with an unknown error"}
  end

  @doc """
  Try to get the access token from Keycloak with the given, preconfigured `OAuth2.Client`.

  ## Examples
      iex> get_token(%OAuth2.Client{...})
      {:ok, %OAuth2.AccessToken{...}}

      iex> get_token(%OAuth2.Client{...})
      {:error, "Getting the access token from Keycloak failed"}
  """
  @spec get_token(OAuth2.Client.t(), keyword(), keyword(), keyword()) :: {:ok, OAuth2.AccessToken.t()} | {:error, binary()}
  def get_token(%OAuth2.Client{} = client, params \\ [], headers \\ [], opts \\ []) when is_list(params) and is_list(headers) and is_list(opts) do
    case OAuth2.Client.get_token(client, params, headers, opts) do
      {:ok, %OAuth2.Client{token: %OAuth2.AccessToken{} = access_token}} ->
        {:ok, access_token}

      _getting_token_failed ->
        {:error, "Getting the access token from Keycloak failed"}
    end
  end
end
