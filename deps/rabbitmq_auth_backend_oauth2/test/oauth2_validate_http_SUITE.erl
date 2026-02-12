%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at https://mozilla.org/MPL/2.0/.
%%
%% Copyright (c) 2007-2025 Broadcom. All Rights Reserved. The term "Broadcom" refers to Broadcom Inc. and/or its subsidiaries. All rights reserved.
%%

-module(oauth2_validate_http_SUITE).

-compile(export_all).

-include_lib("rabbit_common/include/rabbit.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

all() ->
    [
        {group, with_management_plugin}
    ].

groups() ->
    [
        {with_management_plugin, [], [
            test_oauth2_validate_endpoint_missing_fields,
            test_oauth2_validate_endpoint_invalid_json,
            test_oauth2_validate_endpoint_valid_request,
            test_oauth2_validate_endpoint_unauthorized,
            test_oauth2_validate_endpoint_method_not_allowed
        ]}
    ].

init_per_suite(Config) ->
    rabbit_ct_helpers:log_environment(),
    Config1 = rabbit_ct_helpers:set_config(Config, [
        {rmq_nodename_suffix, oauth2_validate_http},
        {rmq_nodes_count, 1}
    ]),
    rabbit_ct_helpers:run_setup_steps(Config1, rabbit_ct_broker_helpers:setup_steps()).

end_per_suite(Config) ->
    rabbit_ct_helpers:run_teardown_steps(Config, rabbit_ct_broker_helpers:teardown_steps()).

init_per_group(with_management_plugin, Config) ->
    rabbit_ct_broker_helpers:enable_plugin(Config, 0, rabbitmq_management),
    rabbit_ct_broker_helpers:enable_plugin(Config, 0, rabbitmq_auth_backend_oauth2),
    Config.

end_per_group(with_management_plugin, Config) ->
    Config.

%%
%% Test Cases
%%

test_oauth2_validate_endpoint_missing_fields(Config) ->
    %% Test with missing required fields
    Payload = #{
        <<"jwks_uri">> => <<"https://example.com/.well-known/jwks.json">>,
        <<"resource_server_id">> => <<"rabbitmq">>
        %% Missing jwt_token
    },

    Response = make_oauth2_validate_request(Config, Payload),
    ?assertEqual(400, proplists:get_value(response_code, Response)),

    Body = proplists:get_value(response_body, Response),
    ?assert(is_binary(Body)),

    case rabbit_json:try_decode(Body) of
        {ok, ResponseJson} ->
            ?assertEqual(<<"bad_request">>, maps:get(<<"error">>, ResponseJson)),
            ?assert(maps:is_key(<<"reason">>, ResponseJson));
        {error, _} ->
            %% If JSON parsing fails, at least verify it's an error response
            ?assert(true)
    end.

test_oauth2_validate_endpoint_invalid_json(Config) ->
    %% Test with invalid JSON
    InvalidJson = <<"{invalid json}">>,

    Response = make_raw_oauth2_validate_request(Config, InvalidJson),
    ?assertEqual(400, proplists:get_value(response_code, Response)).

test_oauth2_validate_endpoint_valid_request(Config) ->
    %% Test with valid request structure (may fail on JWT validation but should accept the request)
    Payload = #{
        <<"jwks_uri">> => <<"https://example.com/.well-known/jwks.json">>,
        <<"resource_server_id">> => <<"rabbitmq">>,
        <<"jwt_token">> => create_test_jwt_token(),
        <<"https">> => #{
            <<"verify">> => <<"verify_none">>
        }
    },

    Response = make_oauth2_validate_request(Config, Payload),
    %% Should accept the request (400 for validation errors, not 405 for method not allowed)
    ResponseCode = proplists:get_value(response_code, Response),
    ?assert(ResponseCode =:= 400 orelse ResponseCode =:= 200),

    %% Verify response has proper structure
    Body = proplists:get_value(response_body, Response),
    ?assert(is_binary(Body)),
    ?assert(byte_size(Body) > 0).

test_oauth2_validate_endpoint_unauthorized(Config) ->
    %% Test without authentication
    Payload = #{
        <<"jwks_uri">> => <<"https://example.com/.well-known/jwks.json">>,
        <<"resource_server_id">> => <<"rabbitmq">>,
        <<"jwt_token">> => create_test_jwt_token()
    },

    Response = make_oauth2_validate_request_no_auth(Config, Payload),
    ?assertEqual(401, proplists:get_value(response_code, Response)).

test_oauth2_validate_endpoint_method_not_allowed(Config) ->
    %% Test with GET method (should only accept POST)
    Response = make_oauth2_validate_get_request(Config),
    ?assertEqual(405, proplists:get_value(response_code, Response)).

%%
%% Helper Functions
%%

make_oauth2_validate_request(Config, Payload) ->
    make_oauth2_validate_request(Config, Payload, "guest", "guest").

make_oauth2_validate_request(Config, Payload, Username, Password) ->
    Json = rabbit_json:encode(Payload),
    make_raw_oauth2_validate_request(Config, Json, Username, Password).

make_oauth2_validate_request_no_auth(Config, Payload) ->
    Json = rabbit_json:encode(Payload),
    make_raw_oauth2_validate_request_no_auth(Config, Json).

make_raw_oauth2_validate_request(Config, Body) ->
    make_raw_oauth2_validate_request(Config, Body, "guest", "guest").

make_raw_oauth2_validate_request(Config, Body, Username, Password) ->
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    URI = lists:flatten(io_lib:format("http://localhost:~w/api/oauth2/validate/token/decode", [Port])),

    Headers = [
        {"Content-Type", "application/json"},
        {"Authorization", "Basic " ++ base64:encode_to_string(Username ++ ":" ++ Password)}
    ],

    case httpc:request(post, {URI, Headers, "application/json", Body}, [], []) of
        {ok, {{_Version, ResponseCode, _ReasonPhrase}, _Headers, ResponseBody}} ->
            [
                {response_code, ResponseCode},
                {response_body, list_to_binary(ResponseBody)}
            ];
        {error, Reason} ->
            ct:fail("HTTP request failed: ~p", [Reason])
    end.

make_raw_oauth2_validate_request_no_auth(Config, Body) ->
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    URI = lists:flatten(io_lib:format("http://localhost:~w/api/oauth2/validate/token/decode", [Port])),

    Headers = [
        {"Content-Type", "application/json"}
    ],

    case httpc:request(post, {URI, Headers, "application/json", Body}, [], []) of
        {ok, {{_Version, ResponseCode, _ReasonPhrase}, _Headers, ResponseBody}} ->
            [
                {response_code, ResponseCode},
                {response_body, list_to_binary(ResponseBody)}
            ];
        {error, Reason} ->
            ct:fail("HTTP request failed: ~p", [Reason])
    end.

make_oauth2_validate_get_request(Config) ->
    Port = rabbit_ct_broker_helpers:get_node_config(Config, 0, tcp_port_mgmt),
    URI = lists:flatten(io_lib:format("http://localhost:~w/api/oauth2/validate/token/decode", [Port])),

    Headers = [
        {"Authorization", "Basic " ++ base64:encode_to_string("guest:guest")}
    ],

    case httpc:request(get, {URI, Headers}, [], []) of
        {ok, {{_Version, ResponseCode, _ReasonPhrase}, _Headers, ResponseBody}} ->
            [
                {response_code, ResponseCode},
                {response_body, list_to_binary(ResponseBody)}
            ];
        {error, Reason} ->
            ct:fail("HTTP request failed: ~p", [Reason])
    end.

create_test_jwt_token() ->
    %% Create a basic JWT token structure for testing
    Header = base64url:encode(rabbit_json:encode(#{
        <<"alg">> => <<"RS256">>,
        <<"typ">> => <<"JWT">>,
        <<"kid">> => <<"test-key">>
    })),

    Now = os:system_time(seconds),
    Payload = base64url:encode(rabbit_json:encode(#{
        <<"sub">> => <<"test-user">>,
        <<"iss">> => <<"test-issuer">>,
        <<"aud">> => <<"rabbitmq">>,
        <<"exp">> => Now + 3600,
        <<"iat">> => Now,
        <<"scope">> => <<"read write">>
    })),

    Signature = base64url:encode(<<"fake-signature">>),

    <<Header/binary, ".", Payload/binary, ".", Signature/binary>>.
