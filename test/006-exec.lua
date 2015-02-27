local function test_exec(req, rsp)
	-- rsp:exec("/test2", {a=1,b={"foo bar","barfoo"}})
	-- rsp:redirect("/test2?a=1&b=foo&b=bar")
	rsp:exec("/static/test.txt")
end

return test_exec
