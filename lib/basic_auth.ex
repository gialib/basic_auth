defmodule BasicAuth do

  @moduledoc """
  Plug for adding basic authentication. Usage:

  ```elixir
  plug BasicAuth, use_config: {:your_app, :your_config}
  ```

  Where :your_app and :your_config should refer to values in your application config.

  In your configuration you can set values directly, eg

  ```elixir

  config :your_app, your_config: [
    username: "admin",
    password: "simple_password",
    realm: "Admin Area"
  ]
  ```

  or choose to get one (or all) from environment variables, eg

  ```elixir
  config :basic_auth, my_auth_with_system: [
    username: {:system, "BASIC_AUTH_USERNAME"},
    password: {:system, "BASIC_AUTH_PASSWORD"},
    realm:    {:system, "BASIC_AUTH_REALM"}
  ]
  ```

  Alternatively you can provide a custom function to the plug to authenticate the user any way
  you want, such as finding the user from a database.

  ```elixir
  plug BasicAuth, callback: &User.find_by_username_and_password/3
  ```

  (or optionally provide a realm)

  ```elixir
  plug BasicAuth, callback: &User.find_by_username_and_password/3, realm: "Area 51"
  ```

  Where :callback is your custom authentication function that takes a conn, username and a
  password and returns a conn.  Your function must return `Plug.Conn.halt(conn)` if authentication
  fails, otherwise you can use `Plug.Conn.assign(conn, :current_user, ...)` to enhance
  the conn with variables or session for your controller.
  """

  @default_realm "Basic Authentication"

  defmodule Configuration do
    @moduledoc false
    defstruct  config_options: nil
  end

  defmodule Callback do
    @moduledoc false
    defstruct callback: nil, realm: nil
  end


  def init([use_config: config_options]) do
    %Configuration{config_options: config_options}
  end

  def init([callback: callback, realm: realm]) do
    %Callback{callback: callback, realm: realm}
  end

  def init([callback: callback]) do
    %Callback{callback: callback, realm: @default_realm}
    end

  def init(_) do
    raise ArgumentError, """

    Usage of BasicAuth using application config:
    plug BasicAuth, use_config: {:your_app, :your_config}

    -OR-
    Using custom authentication function:
    plug BasicAuth, callback: &MyCustom.function/3

    Where :callback takes a conn, username and password and returns a conn.
    """
  end

  def call(conn, options) do
    header_content = Plug.Conn.get_req_header(conn, "authorization")
    respond(conn, header_content, options)
  end

  defp respond(conn, ["Basic " <> encoded], options) do
    case Base.decode64(encoded) do
      {:ok, key} -> check_key(conn, key, options)
      _ ->
        send_unauthorized_response(conn, options)
    end
  end

  defp respond(conn, _, options) do
    send_unauthorized_response(conn, options)
  end

  defp check_key(conn, key, %Callback{callback: callback}) do
    case String.split(key, ":", parts: 2) do
      [username, password] ->
        conn = callback.(conn, username, password)
        if conn.halted do
          send_unauthorized_response(conn, %{})
        else
          conn
        end
      _ ->
        send_unauthorized_response(conn, %{})
    end
  end

  defp check_key(conn, provided_key, %Configuration{config_options: config_options}) do
    if provided_key  == authentication_key(config_options) do
      conn
    else
      send_unauthorized_response(conn, %{realm: realm(config_options)})
    end
  end


  defp send_unauthorized_response(conn, %Configuration{config_options: config_options}) do
    conn
    |> Plug.Conn.put_resp_header("www-authenticate", "Basic realm=\"#{realm(config_options)}\"")
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp send_unauthorized_response(conn, %{realm: realm}) do
    conn
    |> Plug.Conn.put_resp_header("www-authenticate", "Basic realm=\"#{realm}\"")
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp send_unauthorized_response(conn, _) do
    conn
    |> Plug.Conn.send_resp(401, "401 Unauthorized")
    |> Plug.Conn.halt
  end

  defp to_value({:system, env_var}), do: System.get_env(env_var)
  defp to_value(value), do: value

  defp authentication_key(config_options = {app, key}) do
    case Application.fetch_env!(app, key)[:key] do
      nil -> username(config_options) <> ":" <> password(config_options)
      authentication_key -> authentication_key
    end
  end

  defp username({app, key}) do
    app
    |> Application.fetch_env!(key)
    |> Keyword.get(:username)
    |> to_value()
  end

  defp password({app, key}) do
    app
    |> Application.fetch_env!(key)
    |> Keyword.get(:password)
    |> to_value()
  end

  defp realm({app, key}) do
    result = app
    |> Application.fetch_env!(key)
    |> Keyword.get(:realm)
    |> to_value()
    result || @default_realm
  end
end
