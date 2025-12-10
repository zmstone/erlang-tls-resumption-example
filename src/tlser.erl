-module(tlser).

-export([ cipher_suites/1
        , versions/0
        , server_port/0
        , tls_v13_ciphers/0
        , cert_dir/0
        , which_side/0
        , files/0
        , log_level/0
        ]).

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
            ['tlsv1.3','tlsv1.2'];
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
    ["TLS_AES_256_GCM_SHA384",
     "TLS_AES_128_GCM_SHA256",
     "TLS_CHACHA20_POLY1305_SHA256",
     "TLS_AES_128_CCM_SHA256",
     "TLS_AES_128_CCM_8_SHA256"].

cert_dir() ->
    {ok, Pwd} = file:get_cwd(),
    case certs_dir() of
        vendor -> filename:join([Pwd, vendor, which_side()]);
        Type -> filename:join([Pwd, Type])
    end.

certs_dir() ->
    case os:getenv("TLSER_CERTS") of
       false -> rsa;
       "vendor" -> vendor;
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
        case certs_dir() of
            vendor ->
                ["ca.crt", "client.crt", "private.key"];
            _ ->
                Name = atom_to_list(which_side()),
                ["ca.pem", Name ++ ".pem", Name ++ ".key"]
        end,
    Opts = [cacertfile, certfile, keyfile],
    lists:map(fun({OptName, FileName}) ->
                      {OptName, filename:join(Dir, FileName)}
              end, lists:zip(Opts, Files)).

log_level() ->
    case os:getenv("TLSER_LOG_LEVEL") of
        false ->
            notice;
        "debug" ->
            debug
    end.
