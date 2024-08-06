defmodule KloakTest do
  use ExUnit.Case

  describe "Authentication functions" do
    test "authorize_url/1" do
      scope = "openid"
      redirect_uri = "http://localhost:4000"

      assert {:ok, client} = Kloak.Client.new()
      assert {:ok, nonce} = Kloak.generate_nonce()
      assert {:ok, authorize_url} = Kloak.authorize_url(client, scope: scope, state: nonce, redirect_uri: redirect_uri)
      assert %URI{path: authorize_url_path, query: authorize_url_query} = URI.parse(authorize_url)
      assert %{} = authorize_url_query = URI.decode_query(authorize_url_query)

      assert authorize_url_path == "/auth/realms/#{Application.get_env(:kloak, :realm, "INVALID_REALM")}/protocol/openid-connect/auth"
      assert authorize_url_query["client_id"] == Application.get_env(:kloak, :client_id, "INVALID_CLIENT_ID")
      assert authorize_url_query["redirect_uri"] == redirect_uri
      assert authorize_url_query["response_type"] == "code"
      assert authorize_url_query["scope"] == scope
      assert authorize_url_query["state"] == nonce
    end
  end

  describe "Utility functions" do
    test "generate_nonce/0 to generate a nonce with the default size" do
      assert {:ok, nonce} = Kloak.generate_nonce()
      assert String.length(nonce) == 32
    end

    test "generate/1 to generate to generate a nonce with a valid given size" do
      Enum.each(1..10, fn size ->
        assert {:ok, nonce} = Kloak.generate_nonce(size)
        assert String.length(nonce) == size
      end)
    end

    test "generate/1 return an error when an invalid size given" do
      assert match?({:error, "Generating nonce failed due to an invalid given size"}, Kloak.generate_nonce(nil))
    end
  end
end
