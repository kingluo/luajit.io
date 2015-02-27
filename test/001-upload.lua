local upload = require("resty.upload")

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
	form:set_timeout(1000)

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

local function test_upload(req, rsp)
	local data,err = parse_form_data(req)
	if err then error(err) end
	for k,v in pairs(data) do
		rsp:say(k,": ",v)
	end
end

return test_upload
