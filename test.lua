local dns = require("socket.dns")
local pg = require("resty.postgres")
local upload = require("resty.upload")
local ffi = require"ffi"

local function getdb()
	local db = pg:new()
	-- db:set_timeout(3000)
	local ok, err = db:connect({path="/var/run/postgresql/.s.PGSQL.5432",database="test",
		user="test",password="test",compact=false})
	return db,err
end

local function extract_name(res)
	local name, filename
	if res[1] == 'Content-Disposition' then
		name = string.match(res[2], ";%s*name=\"([^\"]+)\"")
		filename = string.match(res[2], ";%s*filename=\"([^\"]+)\"")
	end
	return name, filename
end

local function parse_form_data(req)
	local chunk_size = 4096
	local form, err = upload:new(req, chunk_size)
	if not form then
		return nil,err
	end
	-- form:set_timeout(1000) -- 1 sec

	local data = {}
	local filenames = {}
	local name, filename, file
	while true do
		local typ, res, err = form:read()
		if not typ then
			return nil,err
		end

        if typ == "header" then
            name,filename = extract_name(res)
			-- if filename and schema[name] and schema[name].is_file then
				-- local suffix = filename:match('^.*(%.%w+)$')
				-- filename = '/upload/' .. ngx.md5(ngx.now() .. math.random())
				-- if suffix then
					-- filename = filename .. suffix
				-- end
				-- data[name] = filename
				-- filenames[name] = filename
				-- file = io.open(ngx.config.prefix() .. filename, "w+")
				-- if not file then
					-- return nil,"failed to open file " .. filename
				-- end
			-- end
         elseif typ == "body" then
            if file then
                file:write(res)
			else
				if not res:match('^%s*$') then
					data[name] = res
				end
            end
        elseif typ == "part_end" then
			if file then
				file:close()
				file = nil
			end
        elseif typ == "eof" then
            break
        end
	end

	return data, err, filenames
end

local null = ffi.new("void*")
local function test_redis()
	local redis = require "resty.redis"
	local red = redis:new()

	-- red:set_timeout(1000) -- 1 sec

	-- or connect to a unix domain socket file listened
	-- by a redis server:
	--     local ok, err = red:connect("unix:/path/to/redis.sock")

	local ok, err = red:connect("127.0.0.1", 6379)
	if not ok then
		print("failed to connect: ", err)
		return
	end

	ok, err = red:set("dog", "an animal")
	if not ok then
		print("failed to set dog: ", err)
		return
	end

	print("set result: ", ok)

	local res, err = red:get("dog")
	if not res then
		print("failed to get dog: ", err)
		return
	end

	if res == null then
		print("dog not found.")
		return
	end

	print("dog: ", res)

	red:init_pipeline()
	red:set("cat", "Marry")
	red:set("horse", "Bob")
	red:get("cat")
	red:get("horse")
	local results, err = red:commit_pipeline()
	if not results then
		print("failed to commit the pipelined requests: ", err)
		return
	end

	for i, res in ipairs(results) do
		if type(res) == "table" then
			if not res[1] then
				print("failed to run command ", i, ": ", res[2])
			else
				-- process the table value
			end
		else
			-- process the scalar value
		end
	end

	-- put it into the connection pool of size 100,
	-- with 10 seconds max idle time
	local ok, err = red:set_keepalive(10000, 100)
	if not ok then
		print("failed to set keepalive: ", err)
		return
	end

	-- or just close the connection right away:
	-- local ok, err = red:close()
	-- if not ok then
	--     print("failed to close: ", err)
	--     return
	-- end
end

local function test_shdict()
	local test = require("core.shdict").shared.test
	test:set("foo","bar")
	print(test:get("foo"))
	test:set("foo",98767)
	print(test:get("foo"))
end

local function test_db(rsp)
	local db,err = getdb()
	if err then print(err); os.exit(1); end
	local sqlstr = [[
		select * from send_sms_tbl order by id;
	]]
	local res,err,err_msg,tstatus = db:query(sqlstr)
	if not res then
		print(err)
	else
		for i,v in ipairs(res) do
			coroutine.sleep(1)
			rsp:say(table.concat({v.id, v.sendtime, v.status}, ","), "\n")
			rsp:flush()
		end
	end
	db:set_keepalive()
end

local function test_post_args()
	local args = req:get_post_args()
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

local function test_coroutine(req, rsp)
	local co1 = coroutine.spawn(
		function()
			rsp:say("foo\n")
			rsp:flush()
		end
	)

	local co2 = coroutine.spawn(
		function()
			rsp:say(dns.resolve("localhost", 80), "\n")
			rsp:flush()
			coroutine.sleep(2)
			coroutine.exit(true)
			rsp:say("bar\n")
			rsp:flush()
		end
	)

	print(coroutine.wait(co1))
	print(coroutine.wait(co2))
end

local function test_upload(req, rsp)
	local data,err = parse_form_data(req)
	if err then error(err) end
	for k,v in pairs(data) do
		rsp:say(k,":",v,"\n")
	end
end

return function(req, rsp, cf, extra)
	-- test_shdict()
	-- test_upload(req, rsp)
	-- test_coroutine(req, rsp)
	return rsp:say("hello world! test handler\n")
end
