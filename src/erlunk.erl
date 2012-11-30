-module(erlunk).

-export([login/3,extract_token/1]).



-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.




login(Username, Password, Endpoint)->
    RequestBody=lists:flatten(["username=",Username,"&password=", Password]),
    {ok, {{_, StatusCode, _}, ResponseHeaders, Body}}=httpc:request(post, {lists:flatten([Endpoint, "/servicesNS/admin/search/auth/login"]), [], "application/x-www-form-urlencoded", RequestBody}, [],[]),
    case StatusCode of 
	303->
	    {_,Location}=lists:keyfind("location", 1, ResponseHeaders),
	    io:fwrite("~p", [Location]),
	    {ok, {{_, StatusCode, _}, ResponseHeaders, Body}}=httpc:request(post, {Location, [{"content-length", length(RequestBody)}], "application/x-www-form-urlencoded", RequestBody}, [],[]);
        401-> {err, "Failed to authenticate."};
	200  -> extract_token(Body);
	_ -> err
	      
    end.
	    

extract_token(Body)->
    [Token|_]=lists:nthtail(3,string:tokens(Body, "><")),
    Token.








-ifdef(TEST).


extract_token_test()->
    Token=extract_token("<response>\n<sessionKey>3f13fc5c735186dacffcef4d487959d6</sessionKey>\n</response>"),
    ?assert(Token=:="3f13fc5c735186dacffcef4d487959d6").


-endif.
