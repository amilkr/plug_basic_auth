defmodule PlugBasicAuth do
  @moduledoc """
  A plug for protecting routers with HTTP Basic Auth.

  It expects a `:validation` to be passed as &Mod.fun/1 at initialization.

  The user will be prompted for a username and password upon
  accessing any of the routes using this plug.

  The `:validation` callback would be used to decide if the username and
  password are correct:

  If it returns `{conn, :authorized}`, the username and password are correct
  and the user will be able to access the page.

  If it returns `{conn, :unauthorized}`, the username and password are incorrect
  and the user will be prompted to enter them again.

  ## Example

      defmodule TopSecret do
        import Plug.Conn
        use Plug.Router
        plug PlugBasicAuth, validation: &TopSecret.is_authorized/1
        plug :match
        plug :dispatch

        get '/speakeasy' do
          conn
          |> put_resp_content_type("text/plain")
          |> send_resp(200, "Welcome to the party.")
        end

        def is_authorized({conn, {"Snorky", "Capone"}}), do: {conn, :authorized}
        def is_authorized({conn, _}), do: {conn, :unauthorized}
      end
  """

  import Plug.Conn, only: [get_req_header:  2,
                           put_resp_header: 3,
                           send_resp:       3,
                           halt:            1]

  def init(opts) do
    Keyword.fetch!(opts, :validation)
  end

  def call(conn, validation) do
    conn
    |> get_auth_header
    |> parse_auth
    |> validation.()
    |> respond
  end

  defp get_auth_header(conn) do
    auth = get_req_header(conn, "authorization")
    {conn, auth}
  end

  defp parse_auth({conn, ["Basic " <> encoded_creds | _]}) do
    {:ok, decoded_creds} = Base.decode64(encoded_creds)
    [usr, pwd] = String.split(decoded_creds, ":", parts: 2)
    {conn, {usr, pwd}}
  end
  defp parse_auth({conn, _}), do: {conn, nil}

  defp respond({conn, :authorized}), do: conn
  defp respond({conn, :unauthorized}) do
    conn
    |> put_resp_header("www-authenticate", "Basic realm=\"Private Area\"")
    |> send_resp(401, "")
    |> halt
  end
end
