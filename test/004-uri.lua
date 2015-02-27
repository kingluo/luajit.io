local function print_args(args)
	for k,v in pairs(args) do
		print("key=" .. k)
		if type(v) == "table" then
			for _,v1 in ipairs(v) do
				print("value=" .. v1)
			end
		else
			print("value=" .. tostring(v))
		end
	end
end

local function test_post_args(req, rsp)
	print_args(req:get_post_args())
end

local function test_uri_args(req, rsp)
	print_args(req:get_uri_args())
end

return function(req, rsp)
	if req.method == "GET" then
		return test_uri_args(req, rsp)
	elseif req.method == "POST" then
		return test_post_args(req, rsp)
	end
end
