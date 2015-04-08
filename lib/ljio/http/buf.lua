-- Copyright (C) Jinhua Luo

local type = type
local tostring = tostring
local tinsert = table.insert
local tremove = table.remove
local tconcat = table.concat
local ipairs = ipairs

local function copy_table(dst, t)
	for i = 1, #t do
		local v = t[i]
		local typ = type(v)
		if typ == "table" then
			copy_table(dst, v)
		else
			if typ == "boolean" then
				v = v and "true" or "false"
			elseif typ == "nil" then
				v = "nil"
			elseif typ ~= "string" then
				v = tostring(v)
			end
			tinsert(dst, v)
		end
	end
end

local function copy_values_ll(dst, ...)
	for i = 1, select("#", ...) do
		local v = select(i, ...)
		local typ = type(v)
		if typ == "table" then
			copy_table(dst, v)
		else
			if typ == "boolean" then
				v = v and "true" or "false"
			elseif typ == "nil" then
				v = "nil"
			elseif typ ~= "string" then
				v = tostring(v)
			end
			tinsert(dst, v)
		end
	end
	return dst
end

local tmptbl = {nil, nil, nil, nil, nil}

local function copy_values(eol, ...)
	for i, v in ipairs(tmptbl) do
		tmptbl[i] = nil
	end

	local n = select("#", ...)
	if not eol and n == 1 then
		local v = ...
		local typ = type(v)
		if typ ~= "table" then
			if typ == "boolean" then
				v = v and "true" or "false"
			elseif typ == "nil" then
				v = "nil"
			elseif typ ~= "string" then
				v = tostring(v)
			end
			return v
		end
	end

	copy_values_ll(tmptbl, ...)
	if eol then
		copy_values_ll(tmptbl, eol)
	end

	return tconcat(tmptbl)
end

local bufpool = {}
local n_buf = 0

local function put(self)
	tinsert(bufpool, self)
	n_buf = n_buf + 1
end

local buf_mt = { __index = {put = put} }

local function get()
	if n_buf > 0 then
		local buf = tremove(bufpool)
		for i, v in ipairs(buf) do
			buf[i] = nil
		end
		n_buf = n_buf - 1
		return buf
	else
		return setmetatable({}, buf_mt)
	end
end

return {
	copy_values = copy_values,
	get = get,
}
