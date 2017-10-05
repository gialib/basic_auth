defmodule BasicAuthTest do
  use ExUnit.Case, async: true
  use Plug.Test

  defmodule SimplePlug do
    use DemoPlug, use_config: {:basic_auth, :my_auth}
  end

  describe "custom function" do
    defmodule User do
      def find_by_username_and_password(conn, "robert", "secret:value"), do: conn
      def find_by_username_and_password(conn, _, _), do: Plug.Conn.halt(conn)
    end

    defmodule PlugWithCallback do
      use DemoPlug, callback: &User.find_by_username_and_password/3
    end

    defmodule PlugWithCallbackAndRealm do
      use DemoPlug, callback: &User.find_by_username_and_password/3, realm: "Bob's Kingdom"
    end

    test "no credentials provided" do
      conn = conn(:get, "/")
      |> PlugWithCallback.call([])
      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Basic Authentication\""]
    end

    test "no credentials provided with custom realm" do
      conn = conn(:get, "/")
      |> PlugWithCallbackAndRealm.call([])
      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Bob's Kingdom\""]
    end

    test "wrong credentials provided" do
      header_content = "Basic " <> Base.encode64("bad:credentials")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> PlugWithCallback.call([])
      assert conn.status == 401
    end

    test "right credentials provided" do
      header_content = "Basic " <> Base.encode64("robert:secret:value")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> PlugWithCallback.call([])
      assert conn.status == 200
    end

    test "incorrect basic auth formatting returns a 401" do
      header_content = "Basic " <> Base.encode64("bogus")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> PlugWithCallback.call([])

      assert conn.status == 401
    end
  end

  describe "with username and password from configuration" do

    setup do
      Application.put_env(:basic_auth, :my_auth, username: "admin",
        password: "simple:password", realm: "Admin Area")
    end

    test "no credentials returns a 401" do
      conn = conn(:get, "/")
      |> SimplePlug.call([])

      assert conn.status == 401
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Admin Area\""]
    end

    test "default realm" do
      Application.put_env(:basic_auth, :my_auth, username: "admin", password: "simple:password")
      conn = conn(:get, "/")
      |> SimplePlug.call([])

      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Basic Authentication\""]
    end

    test "invalid credentials returns a 401" do
      header_content = "Basic " <> Base.encode64("bad:credentials")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 401
    end

    test "incorrect header returns a 401" do
      header_content = "Banana " <> Base.encode64("admin:simple:password")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 401
    end

    test "incorrect basic auth formatting returns a 401" do
      header_content = "Basic " <> Base.encode64("bogus")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 401
    end

    test "invalid basic auth base64 encoding returns a 401" do
      header_content = "Basic " <> "malformed base64"

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 401
    end

    test "valid credentials returns a 200" do
      header_content = "Basic " <> Base.encode64("admin:simple:password")

      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 200
    end
  end

  describe "using configured key instead of username and password" do
    defmodule PlugWithKey do
      use DemoPlug, use_config: {:basic_auth, :my_auth_with_key}
    end

    setup do
      Application.put_env(:basic_auth, :my_auth, key: "my:secure:key")
    end

    test "is successful" do
      header_content = "Basic " <> Base.encode64("my:secure:key")
      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> SimplePlug.call([])

      assert conn.status == 200
    end
  end

  describe "configured to get username and password from System" do
    defmodule PlugWithSystem do
      use DemoPlug, use_config: {:basic_auth, :my_auth_with_system}
    end

    test "username and password" do
      System.put_env("USERNAME", "bananauser")
      System.put_env("PASSWORD", "banana:password")

      header_content = "Basic " <> Base.encode64("bananauser:banana:password")
      conn = conn(:get, "/")
      |> put_req_header("authorization", header_content)
      |> PlugWithSystem.call([])

      assert conn.status == 200
    end

    test "realm" do
      System.put_env("REALM", "Banana")
      conn = conn(:get, "/")
      |> PlugWithSystem.call([])
      assert Plug.Conn.get_resp_header(conn, "www-authenticate") == [ "Basic realm=\"Banana\""]
    end
  end
end
