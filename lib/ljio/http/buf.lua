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

local function copy_values_ll(dst, v)
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

local tmptbl = {}

local function copy_value(...)
	local n = select("#", ...)
	if n > 0 then
		local v = ...
		copy_values_ll(tmptbl, v)
		if n > 1 then
			return copy_value(select(2, ...))
		end
	end
end

local function clear_tbl(tbl, i, j)
	i = i or 1
	j = j or #tbl
	if i <= j then
		tbl[i] = nil
		if i < j then
			return clear_tbl(tbl, i + 1, j)
		end
	end
end

local function copy_values(eol, ...)
	tmptbl = {}

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
	
	copy_value(...)
	if eol then
		tinsert(tmptbl, eol)
	end

	return (tconcat(tmptbl))
end

local bufpool = {}
local n_buf = 0

local function put(self)
	tinsert(bufpool, self)
	n_buf = n_buf + 1
end

local buf_mt = { __index = {put = put, clear = clear_tbl} }

local function get()
	if n_buf > 0 then
		local buf = tremove(bufpool)
		buf:clear()
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
