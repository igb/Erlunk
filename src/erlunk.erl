-module(erlunk).

-export([login/3,extract_token/1, search/3, get_job_status/3,get_results/3, download_source/5]).



-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

% "index=release_runner \"Build Failed\""
search(Query, Endpoint, Token)->
     {ok, {{_, StatusCode, _}, ResponseHeaders, Body}}=httpc:request(post, {lists:flatten([Endpoint, "/services/search/jobs"]), [{"Authorization", lists:flatten(["Splunk ", Token])}], "application/x-www-form-urlencoded", lists:flatten(["search=search ",replace_equalsign(Query)])}, [],[]),
    case StatusCode of
	201 ->
	    Sid=extract_sid(Body),
	    get_results_when_ready(Sid, Endpoint, Token);
	_  -> {err, StatusCode}
    end.

get_results_when_ready(Sid, Endpoint, Token)->
    Status=get_job_status(Sid, Endpoint, Token),    
    case Status  of
	"DONE" ->
	    get_results(Sid, Endpoint, Token);
	"FAILED" -> {err, Status};
	"PAUSED" -> {err, Status};
	_ -> io:fwrite("~s~n...", [Status]),
	     timer:sleep(5000),
	     get_results_when_ready(Sid, Endpoint, Token)
    end.


download_source(Index, Source, LocalFile, Endpoint, Token)->
    Query=lists:flatten(["index=", Index, " source=\"", Source, "\""]),
    Results=search(Query, Endpoint, Token),
    FirstToLast=lists:reverse(Results),

    
    

    {ok, FileDescriptor} = file:open(LocalFile, [write]),
    PrintFun=fun(X)-> {{offset,_},Fields}=X,{_,Raw}=lists:keyfind("_raw", 1, Fields),
		      RawLines=re:replace(Raw, "\\\n", "\n", [global, {return, list}]),
		      io:format(FileDescriptor, "~s~n", [RawLines])
	     end,
    lists:map(PrintFun,FirstToLast),
    file:close(FileDescriptor).
    


%% gets ALL the results
get_results(Sid, Endpoint, Token)->
    get_results(Sid, Endpoint, Token, 0, []).


get_results(Sid, Endpoint, Token, Offset, Acc)->
     {ok, {{_, StatusCode, _}, ResponseHeaders, Body}}=httpc:request(get, {lists:flatten([Endpoint, "/services/search/jobs/", Sid, "/results?output_mode=xml&offset=", integer_to_list(Offset)]), [{"Authorization", lists:flatten(["Splunk ", Token])}]}, [],[]),
    case StatusCode of
	200 ->
	    Body,
	    % write to tmp file for debugging...
	    % {ok, FileDescriptor} = file:open("/tmp/output.txt", [write]),
	    % io:format(FileDescriptor, "~s~n~nend~n~n", [Body]),
	    % file:close(FileDescriptor),
	    
	    % parse XML
	    Results=parse_results(Body),
	    case Results of
		no_results->Acc;
		_-> NewAcc=lists:append([Acc,Results]),
		    [{{offset, NewOffsetStr}, _}|_]=lists:nthtail(length(Results) -1, Results),
		    %io:fwrite("new offset: ~p~n",[NewOffsetStr]),
		    {NewOffsetInt,[]}=string:to_integer(NewOffsetStr),
		    get_results(Sid, Endpoint, Token, NewOffsetInt + 1, NewAcc)
	    end;

	
	_  -> {err, StatusCode}
    end.
    

parse_results(Body)->
    {Xml, _}=xmerl_scan:string(Body, [{space, 'normalize'}]),
    SimplifiedXml=xmerl_lib:simplify_element(Xml),
    {results,_,Results}=SimplifiedXml,
    case Results of
	[]->no_results;
	_->
	    [" ", Metadata|ResultData]=Results,
	    Fields=parse_metadata(Metadata),
	    CleanedResultData=strip_whitespace_from_xml(ResultData),
%	    io:fwrite("~p~n", [CleanedResultData]),
	    lists:map(fun(X)->
			      {result,[{offset,Offset}],ResultFields}=X,
			      {{offset, Offset},
			       lists:map(fun(Y)-> 
						 %io:fwrite("~p~n",[Y]),
						 {field,[{k,FieldName}], ValueStruct}=Y,
						 Value=extract_value(ValueStruct),
						 {FieldName, Value}
					 end,
					 strip_whitespace_from_xml(ResultFields)) } 
		      end,
		      CleanedResultData)
    end.



flatten_raw_content(RawContent)->     
    flatten_raw_content(RawContent, []).

flatten_raw_content([H|T], Acc)->
    case H of
	{sg,[_],[Content]}->NewAcc=lists:flatten([Acc, Content]),
			    flatten_raw_content(T, NewAcc);
	Raw -> NewAcc=lists:flatten([Acc,Raw]),
	       flatten_raw_content(T, NewAcc)
	end; 
flatten_raw_content([], Acc)->
    Acc.


extract_value(ValueStruct)->
    case ValueStruct of
	[" ",{value,[],[{text,[],[Value]}]}," "]->Value;
	[" ",{value,[{h,"1"}],[{text,[],[Value]}]}," "]->Value;
	[" ",{value,[],[{text,[],[ValueOne]}]}," ",{value,[],[{text,[],[ValueTwo]}]}," "]->lists:flatten([ValueOne, " ", ValueTwo]);
	[{v,[{'xml:space',"preserve"},{trunc,"0"}], RawValue}]-> flatten_raw_content(RawValue)
    end.

        
parse_metadata(Metadata)->    
    {meta,[],[_,{fieldOrder,[],Fields},_]}=Metadata,
    FilteredFields=strip_whitespace_from_xml(Fields),
    [X || {field,[],[X]} <- FilteredFields].

strip_whitespace_from_xml(XmlStruct)->
    FilteredFields=lists:filter(fun(X)-> X/=" " end, XmlStruct).

get_job_status(Sid, Endpoint, Token)->
    Url=lists:flatten([Endpoint, "/services/search/jobs/", Sid]),
   % io:format("~p~n", [Url]),
    
    {ok, {{_, StatusCode, _}, ResponseHeaders, Body}}=httpc:request(get, {Url, [{"Authorization", lists:flatten(["Splunk ", Token])}]}, [],[]),
    case StatusCode of 
	200 -> {Xml, _}=xmerl_scan:string(Body, [{space, 'normalize'}]),            
	       SimplifiedXml=xmerl_lib:simplify_element(Xml),
	       {entry,_, EntryElements}=SimplifiedXml,
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
	    %io:fwrite("~p", [Location]),
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
    
replace_equalsign(String)->
    Tokens=string:tokens(String,"="),
    [H|T]=Tokens,
    lists:flatten([H, [lists:flatten(["%3d",X])|| X <-T]]).







-ifdef(TEST).


extract_token_test()->
    Token=extract_token("<response>\n<sessionKey>3f13fc5c735186dacffcef4d487959d6</sessionKey>\n</response>"),
    ?assert(Token=:="3f13fc5c735186dacffcef4d487959d6").

extract_sid_test()->
    Sid=extract_sid("<?xml version='1.0' encoding='UTF-8'?>\n<response><sid>1354291037.69</sid></response>"),
    ?assert(Sid=:="1354291037.69").

replace_equalsign_test()->
    Replaced1=replace_equalsign("index=release_runner Error"),
    ?assert(Replaced1=:="index%3drelease_runner Error"),
    Replaced2=replace_equalsign("foo bar Error"),
    ?assert(Replaced2=:="foo bar Error"),
    Replaced3=replace_equalsign("foo=bar=Error"),
    ?assert(Replaced3=:="foo%3dbar%3dError").
      


-endif.
