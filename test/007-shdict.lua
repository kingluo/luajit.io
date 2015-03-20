local function test(req, rsp)
	local test = require("ljio.core.shdict").shared.test
	test:set("foo1","bar222")
	test:set("foo2","bar")
	test:set("foo3","bar")
	test:set("foo4","bar")
	test:set(222,"bar")

	test:replace("foo",98767)

	test:delete("foo")

	rsp:say(test:get(222))
	test:flush_all()
	test:add("bar", 2, 1)
	test:incr("bar", 2)
	rsp:say(test:get("bar"))
	rsp:say(table.concat(test:get_keys(), ","))
end

return test
