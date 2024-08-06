# Kloak
Kloak is a simple wrapper for [OAuth2](https://hex.pm/packages/oauth2), which can be used for authenticating users with [Phoenix](https://hex.pm/packages/phoenix) and a [Keycloak](https://www.keycloak.org/) IDM.

## Installation
The package can be installed by adding `kloak` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:kloak, "~> 0.2.0"}
  ]
end
```

## Usage
Using `Kloak` with a `Phoenix` application is quite easy. To perform authentication with Keycloak, you need to implement at least one `login` and one `callback` controller function e.g. in your `authentication_controller`.

```elixir
@doc "Login controller action which redirects to Keycloak for authentication."
def login(conn, _) do
  with {:ok, client} <- Kloak.Client.new(),
       {:ok, nonce} <- generate_nonce(),
       {:ok, redirect_url} <- Kloak.authorize_url(client, scope: "openid", state: nonce, redirect_uri: url(~p"/auth/callback")) do
    conn
    |> Kloak.put_oidc_state(nonce)
    |> redirect(external: redirect_url)
  end
end
```

```elixir
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
```

## License
The MIT License (MIT). Please see [LICENSE](LICENSE) for more information.

