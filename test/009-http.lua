local function test_http(req, rsp)
  -- For simple singleshot requests, use the URI interface.
  local http = require "resty.http"
  local httpc = http.new()
  local res, err = httpc:request_uri("http://example.com/helloworld", {
    method = "POST",
    body = "a=1&b=2",
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
    },
    keepalive_timeout = 60000,
    keepalive_pool = 10
  })

  if not res then
    ngx.say("failed to request: ", err)
    return
  end

  -- In this simple form, there is no manual connection step, so the body is read
  -- all in one go, including any trailers, and the connection closed or keptalive
  -- for you.

  ngx.status = res.status

  for k,v in pairs(res.headers) do
      --
  end

  ngx.say(res.body)
end
return test_http
