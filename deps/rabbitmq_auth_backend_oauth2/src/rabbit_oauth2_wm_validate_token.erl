%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2007-2025 Broadcom. All Rights Reserved. The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries. All rights reserved.
%%

-module(rabbit_oauth2_wm_validate_token).

-export([init/2]).
-export([content_types_accepted/2, content_types_provided/2, is_authorized/2]).
-export([allowed_methods/2, accept_content/2, to_json/2]).
-export([variances/2]).
-export([validate_jwt_token_on_current_node/2]). % Export for RPC calls

-include_lib("rabbitmq_management_agent/include/rabbit_mgmt_records.hrl").
-include_lib("rabbit_common/include/rabbit.hrl").
-include_lib("rabbitmq_auth_backend_oauth2/include/oauth2.hrl").

-import(uaa_jwt, [decode_and_verify/3]).

%%--------------------------------------------------------------------

init(Req, _State) ->
    {cowboy_rest, rabbit_mgmt_headers:set_common_permission_headers(Req, ?MODULE), #context{}}.

variances(Req, Context) ->
    {[<<"accept-encoding">>, <<"origin">>], Req, Context}.

content_types_provided(ReqData, Context) ->
   {rabbit_mgmt_util:responder_map(to_json), ReqData, Context}.

content_types_accepted(ReqData, Context) ->
    {[{'*', accept_content}], ReqData, Context}.

allowed_methods(ReqData, Context) ->
    {[<<"POST">>], ReqData, Context}.

is_authorized(ReqData, Context) ->
    rabbit_mgmt_util:is_authorized_admin(ReqData, Context).

to_json(ReqData, Context) ->
    rabbit_mgmt_util:reply(#{status => <<"ok">>}, ReqData, Context).

accept_content(ReqData0, Context) ->
    {ok, Body, ReqData} = rabbit_mgmt_util:read_complete_body(ReqData0),
    rabbit_log:info("OAuth2 token validation request body: ~p", [Body]),
    case rabbit_json:try_decode(Body) of
        {ok, Payload} ->
            rabbit_log:info("JSON decoded successfully: ~p", [Payload]),
            case validate_token_payload(Payload) of
                {ok, Result} ->
                    ResultProplist = maps:to_list(Result),
                    {true, cowboy_req:set_resp_body(rabbit_json:encode(ResultProplist), ReqData), Context};
                {error, Error} ->
                    rabbit_log:error("Token validation error: ~p", [Error]),
                    ErrorProplist = maps:to_list(Error),
                    rabbit_mgmt_util:bad_request(ErrorProplist, ReqData, Context)
            end;
        {error, JsonError} ->
            rabbit_log:error("JSON decode error: ~p for body: ~p", [JsonError, Body]),
            ErrorMap = #{
                message => <<"Invalid JSON in request body">>
            },
            rabbit_mgmt_util:bad_request(maps:to_list(ErrorMap), ReqData, Context)
    end.

%%--------------------------------------------------------------------
%% Internal functions
%%--------------------------------------------------------------------

validate_token_payload(Payload) ->
    RequiredFields = [<<"jwks_uri">>, <<"resource_server_id">>, <<"jwt_token">>],
    case check_required_fields(Payload, RequiredFields) of
        {error, _} = Error ->
            Error;
        ok ->
            JwksUri = maps:get(<<"jwks_uri">>, Payload),
            ResourceServerId = maps:get(<<"resource_server_id">>, Payload),
            Token = maps:get(<<"jwt_token">>, Payload),
            HttpsOptions = maps:get(<<"https">>, Payload, #{}),

            put(validation_node, undefined),
            put(validation_peer, undefined),

            try
                % Start a new Erlang node for validation
                NodeName = list_to_atom("oauth2_validate_" ++ integer_to_list(erlang:unique_integer([positive]))),

                {ok, Node} = start_validation_node(NodeName),
                rabbit_log:debug("Started validation node: ~p", [Node]),

                % Run the validation on the new node
                Result = rpc:call(Node, ?MODULE, validate_jwt_token_on_current_node,
                                [Token, #{jwks_uri => JwksUri,
                                         resource_server_id => ResourceServerId,
                                         https_options => HttpsOptions}]),

                case Result of
                    {badrpc, Reason} ->
                        rabbit_log:error("JWT validation RPC error: ~p", [Reason]),
                        {error, #{
                            message => list_to_binary(io_lib:format("JWT validation error: ~p", [Reason]))
                        }};
                    ValidationResult ->
                        ValidationResult
                end
            catch
                E:R:S ->
                    rabbit_log:error("Token validation error: ~p:~p:~p", [E, R, S]),
                    {error, #{
                        message => list_to_binary(io_lib:format("~p", [R])),
                        stacktrace => list_to_binary(io_lib:format("~p", [S]))
                    }}
            after
                case get(validation_peer) of
                    undefined -> ok;
                    Peer ->
                        rabbit_log:debug("Stopping validation node: ~p", [get(validation_node)]),
                        % Stop the peer process
                        unlink(Peer),
                        exit(Peer, normal),
                        erase(validation_peer),
                        erase(validation_node)
                end
            end
    end.

check_required_fields(Payload, RequiredFields) ->
    check_required_fields(Payload, RequiredFields, []).

check_required_fields(_Payload, [], []) ->
    ok;
check_required_fields(_Payload, [], MissingFields) ->
    {error, #{
        message => <<"Missing required fields">>,
        missing_fields => lists:reverse(MissingFields)
    }};
check_required_fields(Payload, [Field | Rest], MissingFields) ->
    case maps:get(Field, Payload, undefined) of
        undefined ->
            check_required_fields(Payload, Rest, [Field | MissingFields]);
        _ ->
            check_required_fields(Payload, Rest, MissingFields)
    end.

start_validation_node(_NodeName) ->
    rabbit_log:debug("Starting validation node with peer module"),

    CodePath = code:get_path(),
    rabbit_log:debug("Code path length: ~p", [length(CodePath)]),

    NodeConfig = #{
        name => list_to_atom("oauth2_validate_" ++ integer_to_list(erlang:unique_integer([positive]))),
        args => []
    },
    rabbit_log:debug("NodeConfig: ~p", [NodeConfig]),

    Result = (catch peer:start_link(NodeConfig)),
    rabbit_log:debug("peer:start_link result: ~p", [Result]),

    case Result of
        {ok, Peer, Node} ->
            put(validation_peer, Peer),
            put(validation_node, Node),

            % Set up the code path on the peer node
            _ = rpc:call(Node, code, set_path, [CodePath]),

            % Start required applications
            _ = rpc:call(Node, application, ensure_all_started, [inets]),
            _ = rpc:call(Node, application, ensure_all_started, [ssl]),
            _ = rpc:call(Node, application, ensure_all_started, [crypto]),
            _ = rpc:call(Node, application, ensure_all_started, [asn1]),
            _ = rpc:call(Node, application, ensure_all_started, [public_key]),

            % Copy essential environment variables from the main node
            case application:get_env(rabbit, feature_flags_file) of
                {ok, FeatureFlagsFile} ->
                    _ = rpc:call(Node, application, set_env, [rabbit, feature_flags_file, FeatureFlagsFile]);
                undefined ->
                    ok
            end,

            case application:get_env(rabbit, enabled_plugins_file) of
                {ok, EnabledPluginsFile} ->
                    _ = rpc:call(Node, application, set_env, [rabbit, enabled_plugins_file, EnabledPluginsFile]);
                undefined ->
                    ok
            end,

            % Set up a minimal data directory for the peer node
            case application:get_env(rabbit, data_dir) of
                {ok, DataDir} ->
                    PeerDataDir = DataDir ++ "_validation_" ++ integer_to_list(erlang:unique_integer([positive])),
                    _ = rpc:call(Node, application, set_env, [rabbit, data_dir, PeerDataDir]);
                undefined ->
                    % Create a temporary data directory
                    TempDataDir = "/tmp/rabbitmq_validation_" ++ integer_to_list(erlang:unique_integer([positive])),
                    _ = rpc:call(Node, application, set_env, [rabbit, data_dir, TempDataDir])
            end,

            % Set up other essential RabbitMQ environment variables
            _ = rpc:call(Node, application, set_env, [rabbit, cluster_nodes, {[], disc}]),
            _ = rpc:call(Node, application, set_env, [rabbit, default_user, <<"guest">>]),
            _ = rpc:call(Node, application, set_env, [rabbit, default_pass, <<"guest">>]),

            % Load required modules
            {module, _} = rpc:call(Node, code, ensure_loaded, [rabbit_oauth2_resource_server]),
            {module, _} = rpc:call(Node, code, ensure_loaded, [uaa_jwt]),
            {module, _} = rpc:call(Node, code, ensure_loaded, [oauth2_client]),

            {ok, Node};
        Error ->
            rabbit_log:error("Failed to start peer node: ~p", [Error]),
            Error
    end.

validate_jwt_token_on_current_node(Token, Config) ->
    ValidationProviderId = <<"oauth2_validation_provider">>,

    try
        JwksUri = maps:get(jwks_uri, Config),
        ResourceServerId = maps:get(resource_server_id, Config),
        HttpsOptions = maps:get(https_options, Config, #{}),

        SslOptions = extract_ssl_options_from_https(HttpsOptions),

        Algorithms = [<<"RS256">>],

        ResourceServer = rabbit_oauth2_resource_server:new_resource_server(ResourceServerId),
        ValidationResourceServer = ResourceServer#resource_server{
            oauth_provider_id = ValidationProviderId
        },

        InternalOAuthProvider = #internal_oauth_provider{
            id = ValidationProviderId,
            default_key = undefined,
            algorithms = Algorithms
        },

        % Create a temporary provider for validation
        CurrentProviders = case application:get_env(rabbitmq_auth_backend_oauth2, oauth_providers) of
            {ok, Providers} -> Providers;
            undefined -> #{}
        end,
        UpdatedProviders = maps:put(ValidationProviderId,
            [{jwks_uri, JwksUri},
                {https, SslOptions}],
            CurrentProviders),

        application:set_env(rabbitmq_auth_backend_oauth2, oauth_providers, UpdatedProviders),

        % Validate the token using uaa_jwt:decode_and_verify/3
        ValidationResult = case decode_and_verify(Token, ValidationResourceServer, InternalOAuthProvider) of
            {true, Fields} ->
                % Check if the token has expired
                Now = os:system_time(seconds),
                case maps:get(<<"exp">>, Fields, undefined) of
                    Exp when is_integer(Exp), Exp =< Now ->
                        Msg = rabbit_misc:format("Provided JWT token has expired at timestamp ~tp (validated at ~tp)", [Exp, Now]),
                        rabbit_log:error(Msg),
                        {ok, #{
                            valid => false,
                            jwks_uri => JwksUri,
                            resource_server_id => ResourceServerId,
                            error => <<"token_expired">>,
                            error_message => list_to_binary(Msg)
                        }};
                    _ ->
                        {ok, #{
                            valid => true,
                            jwks_uri => JwksUri,
                            resource_server_id => ResourceServerId,
                            decoded_token => Fields
                        }}
                end;
            {false, _} ->
                {error, #{
                    message => <<"Invalid JWT token signature">>
                }};
            {error, Reason} ->
                ErrorStr1 = lists:flatten(io_lib:format("JWT validation error: ~p", [Reason])),
                ErrorMessage1 = list_to_binary(re:replace(ErrorStr1, "[\n\s]+", " ", [global, {return, list}])),
                {error, #{
                    message => ErrorMessage1
                }}
        end,

        case application:get_env(rabbitmq_auth_backend_oauth2, oauth_providers) of
            {ok, CleanupProvidersMap} ->
                CleanupCleanedProviders = maps:remove(ValidationProviderId, CleanupProvidersMap),
                application:set_env(rabbitmq_auth_backend_oauth2, oauth_providers, CleanupCleanedProviders);
            _ ->
                ok
        end,
        ValidationResult
    catch
        E:R:S ->
            case application:get_env(rabbitmq_auth_backend_oauth2, oauth_providers) of
                {ok, ErrorProvidersMap} ->
                    ErrorCleanedProviders = maps:remove(ValidationProviderId, ErrorProvidersMap),
                    application:set_env(rabbitmq_auth_backend_oauth2, oauth_providers, ErrorCleanedProviders);
                _ ->
                    ok
            end,
            rabbit_log:error("JWT validation error: ~p:~p:~p", [E, R, S]),
            ErrorStr2 = lists:flatten(io_lib:format("JWT validation error: ~p", [R])),
            ErrorMessage2 = list_to_binary(re:replace(ErrorStr2, "[\n\s]+", " ", [global, {return, list}])),
            {error, #{
                message => ErrorMessage2
            }}
    end.

extract_ssl_options_from_https(HttpsOptions) when is_map(HttpsOptions) ->
    rabbit_log:debug("HTTPS options: ~p", [HttpsOptions]),

    SslOptionsMap = maps:fold(
        fun(Key, Value, Acc) ->
            case Key of
                <<"cacertfile">> ->
                    maps:put(cacertfile, binary_to_list(Value), Acc);
                <<"certfile">> ->
                    maps:put(certfile, binary_to_list(Value), Acc);
                <<"keyfile">> ->
                    maps:put(keyfile, binary_to_list(Value), Acc);
                <<"verify">> ->
                    maps:put(verify, Value, Acc);
                <<"fail_if_no_peer_cert">> ->
                    maps:put(fail_if_no_peer_cert, Value, Acc);
                _ ->
                    Acc
            end
        end,
        #{},
        HttpsOptions
    ),

    rabbit_log:debug("SSL options map: ~p", [SslOptionsMap]),
    SslOptions = oauth2_client:extract_ssl_options_as_list(SslOptionsMap),
    rabbit_log:debug("Extracted SSL options: ~p", [SslOptions]),
    SslOptions;
extract_ssl_options_from_https(_) ->
    [].
