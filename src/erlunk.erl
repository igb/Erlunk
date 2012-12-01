-module(erlunk).

-export([login/3,extract_token/1, search/3, get_job_status/3]).



-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

% "index=release_runner \"Build Failed\""
search(Query, Endpoint, Token)->
     {ok, {{_, StatusCode, _}, ResponseHeaders, Body}}=httpc:request(post, {lists:flatten([Endpoint, "/services/search/jobs"]), [{"Authorization", lists:flatten(["Splunk ", Token])}], "application/x-www-form-urlencoded", lists:flatten(["search=search ",Query])}, [],[]),
    case StatusCode of
	201 ->
	    extract_sid(Body);
	_  -> {err, StatusCode}
    end.


get_job_status(Sid, Endpoint, Token)->
    Url=lists:flatten([Endpoint, "/services/search/jobs/", Sid]),
    io:format("~p~n", [Url]),
    
    {ok, {{_, StatusCode, _}, ResponseHeaders, Body}}=httpc:request(get, {Url, [{"Authorization", lists:flatten(["Splunk ", Token])}]}, [],[]),
    case StatusCode of 
	200 -> {Xml, _}=xmerl_scan:string(Body, [{space, 'normalize'}]),            
	       SimplifiedXml=xmerl_lib:simplify_element(Xml),
	       {entry,_, EntryElements}=SimplifiedXml,
	    %   FilteredEntryElements=lists:filter(fun(X)-> X/=" " end, EntryElements), 
	       {content,[{type,"text/xml"}],
		[" ",
		 {'s:dict',[], ContentDictionaryEntries}|_]}=lists:keyfind(content, 1, EntryElements),
	       {'s:key',[{name,"dispatchState"}],[Status]}=lists:keyfind([{name,"dispatchState"}], 2, ContentDictionaryEntries),
	       Status;
	_ -> {err, StatusCode}
    end.



       


    

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
	    
extract_element_value(Index, Body)->
    [Value|_]=lists:nthtail(Index,string:tokens(Body, "><")),
    Value.
extract_token(Body)->
    extract_element_value(3, Body).

extract_sid(Body)->
    extract_element_value(4, Body).
    






-ifdef(TEST).


extract_token_test()->
    Token=extract_token("<response>\n<sessionKey>3f13fc5c735186dacffcef4d487959d6</sessionKey>\n</response>"),
    ?assert(Token=:="3f13fc5c735186dacffcef4d487959d6").

extract_sid_test()->
    Sid=extract_sid("<?xml version='1.0' encoding='UTF-8'?>\n<response><sid>1354291037.69</sid></response>"),
    ?assert(Sid=:="1354291037.69").

-endif.
