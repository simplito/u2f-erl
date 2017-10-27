-module(u2f).

-include_lib("public_key/include/public_key.hrl").

-export([
  register_request/2,
  sign_request/2,
  register/2,
  authenticate/3,
  challenge/0,
  json_encode/1,
  json_decode/1,
  certificate_subject/1
]).

-define(U2F_VERSION, <<"U2F_V2">>).

-define(appId, <<"appId">>).
-define(version, <<"version">>).
-define(origin, <<"origin">>).
-define(counter, <<"counter">>).
-define(enrollmentTime, <<"enrollmentTime">>).
-define(challenge, <<"challenge">>).
-define(registrationData, <<"registrationData">>).
-define(signatureData, <<"signatureData">>).
-define(clientData, <<"clientData">>).
-define(keyHandle, <<"keyHandle">>).
-define(registeredKeys, <<"registeredKeys">>).
-define(registerRequests, <<"registerRequests">>).
-define(attestationCertificate, <<"attestationCertificate">>).
-define(publicKey, <<"publicKey">>).

-type register_request() :: #{ binary() => binary() }.
-type register_response() :: #{ binary() => binary() }.
-type sign_request() :: #{ binary() => binary() }.
-type sign_response() :: #{ binary() => binary() }.
-type registration() :: #{ binary() => binary() | integer()}.

-spec register_request(string() | binary(), [registration()]) -> register_request().
register_request(AppId, Registrations) when is_list(AppId) ->
  register_request( list_to_binary(AppId), Registrations );
register_request(AppId, Registrations) ->
  #{ ?appId => AppId,
     ?registerRequests => [#{ ?version => ?U2F_VERSION, ?challenge => challenge() }],
     ?registeredKeys   => [#{ ?version => ?U2F_VERSION, ?keyHandle => KeyHandle} || #{ ?keyHandle := KeyHandle } <- Registrations]
  }.

-spec sign_request(string() | binary(), [registration()]) -> sign_request().
sign_request(AppId, Registrations) when is_list(AppId) ->
  sign_request( list_to_binary(AppId), Registrations );
sign_request(AppId, Registrations) ->
  #{ ?challenge => challenge(), ?appId => AppId, ?registeredKeys => [#{ ?version => ?U2F_VERSION, ?keyHandle => KeyHandle} || #{ ?keyHandle := KeyHandle } <- Registrations]}.

-spec challenge() -> binary().
challenge() ->
  base64url:encode( crypto:strong_rand_bytes(32) ).

-spec register(Request, Response) -> registration()
  when
    Request  :: binary() | register_request(),
    Response :: binary() | register_response().
register(Request, Response) when not is_map(Request) ->
  ?MODULE:register(json_decode(Request), Response);
register(Request, Response) when not is_map(Response) ->
  ?MODULE:register(Request, json_decode(Response));
register(Request, Response) ->
  #{ ?clientData := B64ClientData, ?registrationData := B64RegistrationData } = Response,
  #{ ?appId := AppId, ?registerRequests := RegisterRequests } = Request,

  ClientData = base64url:decode(B64ClientData),
  ClientDataDecoded = json_decode(ClientData),
  #{ ?challenge := B64Challenge, ?origin := _Origin } = ClientDataDecoded,

  find_challenge(B64Challenge, RegisterRequests),

  RegistrationData = base64url:decode(B64RegistrationData),
  <<5,UserPublicKey:65/binary, L, KeyHandle:L/binary, Rest/binary>> = RegistrationData,

  CertificateDerSize = der_length(Rest),
  <<CertificateDer:CertificateDerSize/binary, Signature/binary>> = Rest,

  Certificate = public_key:pkix_decode_cert(CertificateDer, otp),

  CertificatePublicKey = certificate_public_key(Certificate),

  DataToVerify =
    <<0,
    (crypto:hash(sha256, AppId))/binary,
    (crypto:hash(sha256, ClientData))/binary,
    KeyHandle/binary,
    UserPublicKey/binary>>,

  true = public_key:verify(DataToVerify, sha256, Signature, CertificatePublicKey),

  #{
    ?keyHandle => base64url:encode(KeyHandle),
    ?publicKey => base64url:encode(UserPublicKey),
    ?enrollmentTime => os:system_time(millisecond),
    ?attestationCertificate => base64url:encode(CertificateDer),
    ?counter => -1
  }.

-spec authenticate(Request, Response, Registration) -> registration()
  when
    Request  :: sign_request() | map() | binary(),
    Response :: sign_response() | map() | binary(),
    Registration :: registration() | [registration()].
authenticate(Request, Response, Registration) when not is_map(Request) ->
  authenticate(json_decode(Request), Response, Registration);
authenticate(Request, Response, Registration) when not is_map(Response) ->
  authenticate(Request, json_decode(Response), Registration);
authenticate(Request, Response, Registrations) when is_list(Registrations) ->
  #{ ?keyHandle := KeyHandle } = Response,
  Registration = find_registration_by_handle(KeyHandle, Registrations),
  authenticate(Request, Response, Registration);
authenticate(Request, Response, Registration) ->
  #{ ?challenge := B64Challenge, ?appId := AppId } = Request,
  #{ ?clientData := B64ClientData, ?keyHandle := B64KeyHandle, ?signatureData := B64SignatureData } = Response,
  #{ ?publicKey := B64UserPublicKey, ?keyHandle := B64KeyHandle, ?counter := RegCounter } = Registration,

  ClientData = base64url:decode(B64ClientData),
  ClientDataDecoded = json_decode(ClientData),
  #{ ?challenge := B64Challenge, ?origin := _Origin } = ClientDataDecoded,

  SignatureData = base64url:decode(B64SignatureData),
  <<UserPresence, Counter:32, Signature/binary>> = SignatureData,
  true = (RegCounter =< Counter),

  DataToVerify =
    <<(crypto:hash(sha256,AppId))/binary,
      UserPresence,
      Counter:32,
      (crypto:hash(sha256,ClientData))/binary>>,

  UserPublicKey = base64url:decode(B64UserPublicKey),
  true = crypto:verify(ecdsa, sha256, DataToVerify, Signature, [UserPublicKey, prime256v1]),
  Registration#{ ?counter := Counter }.

json_encode(Data) -> jiffy:encode(Data).
json_decode(Data) -> jiffy:decode(Data, [return_maps]).

%% Internal

find_challenge(Challenge, []) ->
  throw({error, {unknown_challenge, Challenge}});
find_challenge(Challenge, [#{ ?challenge := Challenge } = Request|_]) ->
  Request;
find_challenge(Challenge, [_|TL]) ->
  find_challenge(Challenge, TL).

find_registration_by_handle(KeyHandle, []) ->
  throw({error, {unknown_registration, KeyHandle}});
find_registration_by_handle(KeyHandle, [#{ ?keyHandle := KeyHandle } = Registration|_]) ->
  Registration;
find_registration_by_handle(KeyHandle, [_|TL]) ->
  find_registration_by_handle(KeyHandle, TL).

certificate_subject(B64Certificate) when is_binary(B64Certificate) ->
  Certificate = public_key:pkix_decode_cert(base64url:decode(B64Certificate), otp),
  certificate_subject(Certificate);
certificate_subject(Certificate) ->
  Subject = Certificate#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject,
  case Subject of
    {rdnSequence, [[#'AttributeTypeAndValue'{ type = {2,5,4,3}, value = {utf8String, Value} }]]} ->
      Value;
    _ ->
      <<>>
  end.
  
certificate_public_key(Certificate) ->
  KeyInfo = Certificate#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo,
  case KeyInfo#'OTPSubjectPublicKeyInfo'.algorithm of
    #'PublicKeyAlgorithm'{ algorithm = {1,2,840,113549,1,1,1} } ->
      KeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey;
    #'PublicKeyAlgorithm'{ algorithm = {1,2,840,10045,2,1}, parameters = Parameters } ->
      {KeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey, Parameters};
    Algorithm -> throw({error, {unsupported_pki_algorithm, Algorithm}})
  end.

-spec der_length(binary()) -> pos_integer().
der_length(<<_Tag, 0:1, L:7, _/binary>>) ->
  L;
der_length(<<_Tag, 128, _/binary>>)->
  throw({error, unsupported_indefinite_length});
der_length(<<_Tag, 1:1, LL:7, L:LL/integer-big-unit:8, _/binary>>)->
  2 + L + LL.
