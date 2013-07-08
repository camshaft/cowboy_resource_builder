-module(cowboy_resource_builder).

-export([authorize/4]).
-export([authorize/5]).

authorize(Scopes, Req, Body, Restricted)->
  case cowboy_resource_owner:is_authorized(Scopes, Req) of
    true -> Body ++ Restricted;
    false -> Body
  end.

authorize(UserID, Scopes, Req, Body, Restricted) when is_binary(UserID) ->
  authorize([UserID], Scopes, Req, Body, Restricted);
authorize([], _, _, Body, _) ->
  Body;
authorize([UserID|UserIDs], Scopes, Req, Body, Restricted) when is_list(UserIDs) ->
  case cowboy_resource_owner:owner_id(Req) of
    UserID ->
      authorize(Scopes, Req, Body, Restricted);
    _ ->
      authorize(UserIDs, Scopes, Req, Body, Restricted)
  end.
