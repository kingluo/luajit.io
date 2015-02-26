local function test(req, rsp)
	local lock = require "resty.lock"
	for i = 1, 2 do
		local lock = lock:new("my_locks")

		local elapsed, err = lock:lock("my_key")
		rsp:say("lock: ", elapsed, ", ", err)

		local ok, err = lock:unlock()
		if not ok then
			rsp:say("failed to unlock: ", err)
		end
		rsp:say("unlock: ", ok)
	end
end

return test
