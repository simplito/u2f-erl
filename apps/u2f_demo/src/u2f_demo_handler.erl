-module(u2f_demo_handler).

-export([
  init/3,
  handle/2,
  terminate/3
]).

-define(API_ID, <<"http://localhost:8080">>).

init({_,http}, Req, _Opts) ->
  Req3 =
    case cowboy_req:cookie(<<"sid">>, Req) of
      {undefined, Req2} -> 
        Sid = base64url:encode( crypto:strong_rand_bytes(32) ),
        cowboy_req:set_resp_cookie(<<"sid">>, Sid, [], Req2);
      {Sid, Req2} ->
        Req2
    end,
 
  case cowboy_req:has_body(Req3) of
  false ->
    {ok, ResponseBody} = index_view:render(),
    {ok, Reply} = cowboy_req:reply(200, [{<<"content-type">>, <<"text/html">>}], ResponseBody, Req3),
    {ok, Reply, []};
  true ->
    {ok, Body, Req4} = cowboy_req:body(Req3, []),
    try 
        Data = jiffy:decode(Body, [return_maps]),
        case maps:get(<<"action">>, Data, none) of
        none -> 
          {ok, Reply} = cowboy_req:reply(200, [{<<"content-type">>, <<"application/json">>}], <<"null">>, Req4),
          {ok, Reply, []};
        <<"reset">> ->
          ets:delete_all_objects(sessions),
          {ok, Reply} = cowboy_req:reply(200, [{<<"content-type">>, <<"application/json">>}], <<"{\"success\":true}">>, Req4),
          {ok, Reply, []};
        <<"registerRequest">> ->
          RegisterRequest = register_request(Sid),
          {ok, Reply} = cowboy_req:reply(200, [{<<"content-type">>, <<"application/json">>}], u2f:json_encode(RegisterRequest), Req4),
          {ok, Reply, []};
        <<"register">> ->
          RegisterRequest = get_register_request(Sid),
          RegisterResponse = maps:get(<<"response">>, Data),
          Registration = u2f:register(RegisterRequest, RegisterResponse),
          EnrollmentTime = erlang:list_to_binary(erlang:integer_to_list(maps:get(<<"enrollmentTime">>, Registration))),
          DeviceName = u2f:certificate_subject( maps:get(<<"attestationCertificate">>, Registration)),
          FullName = <<DeviceName/binary, " ", EnrollmentTime/binary>>,
          Response = #{ keyHandle => maps:get(<<"keyHandle">>, Registration),
                        certificateSubject => FullName,
                        counter => maps:get(<<"counter">>, Registration)
                      },
          ets:insert(sessions, {{Sid, registration}, Registration}),
          {ok, Reply} = cowboy_req:reply(200, [{<<"content-type">>, <<"application/json">>}], u2f:json_encode(Response), Req4),
          {ok, Reply, []};
        <<"sign">> ->
          SignRequest = sign_request(Sid),
          {ok, Reply} = cowboy_req:reply(200, [{<<"content-type">>, <<"application/json">>}], u2f:json_encode(SignRequest), Req4),
          {ok, Reply, []};
        <<"authenticate">> ->
          Registrations = get_registrations(Sid),
          SignRequest  = get_sign_request(Sid),
          SignResponse = maps:get(<<"response">>, Data),
          Registration2 = u2f:authenticate(SignRequest, SignResponse, Registrations),
          ets:insert(sessions, {{Sid, registration}, Registration2}),
          Result = #{ keyHandle => maps:get(<<"keyHandle">>, Registration2),
                      certificateSubject => u2f:certificate_subject( maps:get(<<"attestationCertificate">>, Registration2)),
                      counter => maps:get(<<"counter">>, Registration2)
                    },
          {ok, Reply} = cowboy_req:reply(200, [{<<"content-type">>, <<"application/json">>}], u2f:json_encode(Result), Req4),
          {ok, Reply, []}
        end
    catch E:C ->
      Error = iolist_to_binary(io_lib:format("~p:~p", [E,C])),
      {ok, R} = cowboy_req:reply(200, [{<<"content-type">>, <<"application/json">>}], u2f:json_encode(#{ error => Error}), Req4),
      {ok, R, []}
    end
  end.

handle(Req, State) ->
  {ok, Req, State}.

terminate(_,_,_) ->
  ok.

register_request(Sid) ->
  Registrations = get_registrations(Sid),
  Request = u2f:register_request(?API_ID, Registrations),
  ets:insert(sessions, {{Sid, register_request}, Request}),
  Request.

get_register_request(Sid) ->
  case ets:lookup(sessions, {Sid, register_request}) of
  [] ->
    register_request(Sid);
  [{_, Request}] ->
    Request
  end.

sign_request(Sid) ->
  Registrations = get_registrations(Sid),
  Request = u2f:sign_request(?API_ID, Registrations),
  ets:insert(sessions, {{Sid, sign_request}, Request}),
  Request.

get_sign_request(Sid) ->
  case ets:lookup(sessions, {Sid, sign_request}) of
  [] -> 
    sign_request(Sid);
  [{_, Request}] ->
    Request
  end.

get_registrations(Sid) ->
  [Registration || {_,Registration} <- ets:lookup(sessions, {Sid, registration})].
