-module(cowboy_resource_builder).

-export([authorize/4]).

authorize(Scopes, Req, Body, Restricted)->
  case cowboy_resource_owner:is_authorized(Scopes, Req) of
    true -> Body ++ Restricted;
    false -> Body
  end.
