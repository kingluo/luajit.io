local co = require("core.co_mod")
local dns = require("socket.dns_mod")
local pg = require("resty.postgres")
local upload = require("resty.upload")

local function getdb()
	local db = pg:new()
	db:set_timeout(3000)
	local ok, err = db:connect({host="127.0.0.1",port=5432,database="test",
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

local function service(req, rsp, cf, extra)
	-- local co1 = co.spawn(function() co.yield(); co.sleep(2); rsp:say("hello world, conf ok!\n") end)
	-- local co2 = co.spawn(function() rsp:say("hello xxx, conf ok!\n") end)
	-- co.sleep(0.2)
	-- assert(co.wait(co1))
	-- assert(co.wait(co2))
	--while true do
	-- print(dns.resolve("localhost", 80))
	-- collectgarbage()
	--end
	-- local data,err = parse_form_data(req)
	-- for k,v in pairs(data) do
		-- print(k,v)
	-- end

	-- local db,err = getdb()
	-- if err then print(err); os.exit(1); end
	-- local sqlstr = [[
		-- select * from send_sms_tbl order by id;
	-- ]]
	-- local res,err,err_msg,tstatus = db:query(sqlstr)
	-- if not res then
		-- print(err)
	-- else
		-- for i,v in ipairs(res) do
			-- print(v.id, v.sendtime, v.status)
		-- end
	-- end
	-- db:set_keepalive()
	-- local args = req:get_post_args()
	-- for k,v in pairs(args) do
		-- print("key=" .. k)
		-- if type(v) == "table" then
			-- for _,v1 in ipairs(v) do
				-- print("value=" .. v1)
			-- end
		-- else
			-- print("value=" .. tostring(v))
		-- end
	-- end
	return rsp:say("hello world, conf ok!\n")
end

return service
