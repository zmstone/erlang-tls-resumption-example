-module(tlser).

-export([
    cipher_suites/1,
    versions/0,
    tls_version/0,
    server_port/0,
    tls_v13_ciphers/0,
    cert_dir/0,
    which_side/0,
    files/0,
    log_level/0,
    start/0,
    client_no_host_check/0,
    log/2,
    log/3
]).

start() ->
    tlser_session_cache = tlser_session_cache:module_info(module),
    {ok, [_ | _]} = application:ensure_all_started(ssl),
    {ok, [_ | _]} = application:ensure_all_started(tlser),
    ok.

cipher_suites(server) ->
    case os:getenv("TLSER_CLIENT_CIPHERS") of
        false -> ssl:cipher_suites(all, 'tlsv1.2', openssl) ++ tls_v13_ciphers();
        Other -> string:tokens(Other, ",")
    end;
cipher_suites(client) ->
    case os:getenv("TLSER_CLIENT_CIPHERS") of
        false -> ssl:cipher_suites(all, 'tlsv1.2', openssl) ++ tls_v13_ciphers();
        Other -> string:tokens(Other, ",")
    end.

versions() ->
    case os:getenv("TLSER_TLS_ERSIONS") of
        false ->
            ['tlsv1.3', 'tlsv1.2'];
        Other ->
            parse_versions(Other)
    end.

parse_versions(Str) ->
    [parse_version(Token) || Token <- string:tokens(Str, ",")].

parse_version("1.1") -> 'tlsv1.1';
parse_version("1.2") -> 'tlsv1.2';
parse_version("1.3") -> 'tlsv1.3'.

server_port() ->
    case os:getenv("TLSER_SERVER_PORT") of
        false -> 9999;
        N -> list_to_integer(N)
    end.

tls_v13_ciphers() ->
    [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256"
    ].

cert_dir() ->
    {ok, Pwd} = file:get_cwd(),
    Type = certs_dir(),
    filename:join([Pwd, Type]).

certs_dir() ->
    case os:getenv("TLSER_CERTS") of
        false -> rsa;
        Dir -> Dir
    end.

which_side() ->
    case os:getenv("TLSER_START") of
        "server" -> server;
        "client" -> client
    end.

files() ->
    Dir = cert_dir(),
    io:format(user, "using certs in: ~s~n", [Dir]),
    Files =
        case which_side() of
            client ->
                ["ca.pem", "client-cert.pem", "client-key.pem"];
            server ->
                ["ca.pem", "cert.pem", "key.pem"]
        end,
    Opts = [cacertfile, certfile, keyfile],
    lists:map(
        fun({OptName, FileName}) ->
            {OptName, filename:join(Dir, FileName)}
        end,
        lists:zip(Opts, Files)
    ).

log_level() ->
    case os:getenv("TLSER_LOG_LEVEL") of
        false ->
            notice;
        "debug" ->
            debug
    end.

tls_version() ->
    case os:getenv("TLSER_TLS_VERSION") of
        false ->
            % Use both TLS 1.2 and 1.3
            undefined;
        "1.2" ->
            'tlsv1.2';
        "1.3" ->
            'tlsv1.3';
        Other ->
            % Try to parse as version atom
            case Other of
                "tlsv1.2" -> 'tlsv1.2';
                "tlsv1.3" -> 'tlsv1.3';
                _ -> undefined
            end
    end.

client_no_host_check() ->
    case os:getenv("TLSER_CLIENT_NO_HOST_CHECK") of
        "1" -> true;
        "true" -> true;
        "yes" -> true;
        _ -> false
    end.

% Logging with color support
% Levels: error (red), success (green), info (no color)
log(Level, Format) ->
    log(Level, Format, []).

log(error, Format, Args) ->
    % Ensure reset code comes before newline to avoid extra blank lines
    case lists:suffix("~n", Format) of
        true ->
            Base = lists:sublist(Format, length(Format) - 2),
            io:put_chars(user, "\033[31m"),
            io:format(user, Base, Args),
            io:put_chars(user, "\033[0m"),
            io:format(user, "~n", []);
        false ->
            io:put_chars(user, "\033[31m"),
            io:format(user, Format, Args),
            io:put_chars(user, "\033[0m")
    end;
log(success, Format, Args) ->
    % Ensure reset code comes before newline to avoid extra blank lines
    case lists:suffix("~n", Format) of
        true ->
            Base = lists:sublist(Format, length(Format) - 2),
            io:put_chars(user, "\033[32m"),
            io:format(user, Base, Args),
            io:put_chars(user, "\033[0m"),
            io:format(user, "~n", []);
        false ->
            io:put_chars(user, "\033[32m"),
            io:format(user, Format, Args),
            io:put_chars(user, "\033[0m")
    end;
log(info, Format, Args) ->
    io:format(user, Format, Args);
log(_Level, Format, Args) ->
    io:format(user, Format, Args).
