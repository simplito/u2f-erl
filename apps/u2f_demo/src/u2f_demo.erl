-module(u2f_demo).

-export([http_start/0]).

http_start() ->
  do_cowboy_start().

do_cowboy_start() ->
  {Ip, Port, Workers, Dispatch} = do_cowboy_configure(),
  io:format("~nvisit http://localhost:~p ...~n", [Port]),
  cowboy:start_http(http, Workers,
    [{ip, Ip}, {port, Port}],
    [{env, [{dispatch, Dispatch}]}]
  ).

do_cowboy_configure() ->
  {ok, Ip} = application:get_env(?MODULE, ip_address),
  {ok, Port} = application:get_env(?MODULE, port),
  {ok, Workers} = application:get_env(?MODULE, workers),
  Dispatch = cowboy_router:compile([
    {'_', [
      {"/", u2f_demo_handler, []},
      {"/static/[...]", cowboy_static, {priv_dir, u2f_demo, "static"}},
      {"/[...]", cowboy_static, {priv_dir, u2f_demo, "pages"}}
    ]}
  ]),
  {Ip, Port, Workers, Dispatch}.
