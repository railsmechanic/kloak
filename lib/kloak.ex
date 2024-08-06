defmodule Kloak do
  @moduledoc """
  This module is as a simple wrapper around `OAuth2`, which helps building a valid configuration for authorizing with a [Keycloak](http://www.keycloak.org/) server.

  ## Examples

  #### Phoenix controller
      @doc "Login controller action which redirects to Keycloak for authentication."
      def login(conn, _) do
        with {:ok, client} <- Kloak.Client.new(),
             {:ok, nonce} <- Kloak.generate_nonce(),
             {:ok, redirect_url} <- Kloak.authorize_url(client, scope: "openid", state: nonce, redirect_uri: url(~p"/auth/callback")) do
          conn
          |> Kloak.put_oidc_state(nonce)
          |> redirect(external: redirect_url)
        end
      end

      @doc "Callback controller action which is called when a users is redirected from Keycloak."
      def callback(conn, %{"code" => code, "state" => state}) do
        with {:ok, true} <- Kloak.verify_oidc_state(conn, state),
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

  ## -- Module attributes
  # - Default nonce size
  @default_nonce_size 32
  #
  # - Default OIDC state key
  @default_oidc_state_key :oidc_state

  ## -- Authentication functions

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

  ## -- OpenID Connect helper functions
  @doc """
  Put the OpenID Connect state into the session in order to be able to verify that an authentication is requested by the actual user.

  ## Examples
      iex> put_oidc_state(%Plug.Conn{}, "somestate")
      %Plug.Conn{...}

      iex> put_oidc_state(%Plug.Conn{}, "somestate", :extra_oidc_state_key)
      %Plug.Conn{...}
  """
  @spec put_oidc_state(conn :: Plug.Conn.t(), oidc_state :: binary(), oidc_state_key :: atom()) :: Plug.Conn.t()
  def put_oidc_state(%Plug.Conn{} = conn, oidc_state, oidc_state_key \\ @default_oidc_state_key) when is_binary(oidc_state) and byte_size(oidc_state) > 0 and is_atom(oidc_state_key) do
    Plug.Conn.put_session(conn, oidc_state_key, oidc_state)
  end

  @doc """
  Delete the OpenID Connect state from the session of the current user.

  ## Examples
      iex> delete_oidc_state(%Plug.Conn{})
      %Plug.Conn{...}

      iex> delete_oidc_state(%Plug.Conn{}, :extra_oidc_state_key)
      %Plug.Conn{...}
  """
  @spec delete_oidc_state(conn :: Plug.Conn.t(), oidc_state_key :: atom()) :: Plug.Conn.t()
  def delete_oidc_state(%Plug.Conn{} = conn, oidc_state_key \\ @default_oidc_state_key) when is_atom(oidc_state_key) do
    Plug.Conn.delete_session(conn, oidc_state_key)
  end

  @doc """
  Verify the OpenID Connect state from the redirect with the state stored in the session of the current user.

  ## Examples
      iex> verify_oidc_state(%Plug.Conn{}, "statefromredirection")
      {:ok, true}

      iex> verify_oidc_state(%Plug.Conn{}, "invalidstatefromredirection")
      {:ok, false}

      iex> verify_oidc_state(%Plug.Conn{}, "somestate", :extra_oidc_state_key)
      {:error, "Unable to retrieve OIDC state from session"}

      iex> verify_oidc_state(%Plug.Conn{}, nil, nil)
      {:error, "Unable to verify invalid OIDC state with invalid attributes"}
  """
  @spec verify_oidc_state(conn :: Plug.Conn.t(), oidc_state :: binary(), oidc_state_key :: atom()) :: {:ok, boolean()} | {:error, binary()}
  def verify_oidc_state(conn, oidc_state, oidc_state_key \\ @default_oidc_state_key)

  def verify_oidc_state(%Plug.Conn{} = conn, oidc_state, oidc_state_key) when is_binary(oidc_state) and byte_size(oidc_state) > 0 and is_atom(oidc_state_key) do
    case Plug.Conn.get_session(conn, oidc_state_key, :error) do
      session_state when is_binary(session_state) and byte_size(session_state) > 0 ->
        {:ok, String.equivalent?(oidc_state, session_state)}

      _invalid_session_state ->
        {:error, "Unable to retrieve OIDC state from session"}
    end
  end

  def verify_oidc_state(%Plug.Conn{}, _oidc_state, _oidc_state_key) do
    {:error, "Unable to verify invalid OIDC state with invalid attributes"}
  end

  ## -- Utility functions
  @doc """
  Generate a unique, secure random nonce of the given size.

  ## Examples
      iex> generate_nonce()
      {:ok, "aas7d8ads8789asd7981aas7d8ads87d"}

      iex> generate_nonce(8)
      {:ok, "aas7d8ad"}

      iex> generate_nonce(8)
      {:error, "Generating nonce failed with an invalid result"}

      iex> generate_nonce(nil)
      {:error, "Generating nonce failed due to an invalid given size"}
  """
  @spec generate_nonce(non_neg_integer()) :: {:ok, binary()} | {:error, binary()}
  def generate_nonce(size \\ @default_nonce_size)

  def generate_nonce(size) when is_integer(size) and size > 0 do
    case nonce_generator(size) do
      nonce when is_binary(nonce) and byte_size(nonce) == size ->
        {:ok, nonce}

      _invalid_nonce ->
        {:error, "Generating nonce failed with an invalid result"}
    end
  end

  def generate_nonce(_size) do
    {:error, "Generating nonce failed due to an invalid given size"}
  end

  # - Performs the nonce generation of the given size.
  @spec nonce_generator(non_neg_integer(), binary()) :: binary()
  defp nonce_generator(size, acc \\ "")

  defp nonce_generator(size, acc) when is_integer(size) and size > 0 and is_binary(acc) and byte_size(acc) >= size,
    do: String.slice(acc, 0, size)

  defp nonce_generator(size, acc) when is_integer(size) and size > 0 and is_binary(acc) and byte_size(acc) < size,
    do: nonce_generator(size, String.trim(acc <> do_generate_random_token(size)))

  defp nonce_generator(size, _acc) when is_integer(size) and size > 0,
    do: nonce_generator(size, "")

  # - Generate a random Base58 encoded token.
  @spec do_generate_random_token(non_neg_integer()) :: binary()
  defp do_generate_random_token(size) when is_integer(size) and size > 0 do
    size
    |> :crypto.strong_rand_bytes()
    |> Base58.encode()
  end

  defp do_generate_random_token(_invalid_size),
    do: do_generate_random_token(@default_nonce_size)
end
