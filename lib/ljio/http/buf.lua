-- Copyright (C) Jinhua Luo

local select = select
local type = type
local tostring = tostring
local rawset = rawset
local tinsert = table.insert

local function append(a, val, ...)
    if type(val) ~= "string" then
        val = tostring(val)
    end
    tinsert(a, val)
    if select("#", ...) > 0 then
        return append(a, ...)
    end
end

local function truncate(a, idx)
    if idx == nil then
        idx = 1
    end
    for i = idx, #a do
        rawset(a, i, nil)
    end
end

local function calc_size(tbl, buf)
	if buf == nil then
		buf = tbl
		buf.size = 0
	end

	for i = 1, #tbl do
		local v = tbl[i]
		local typ = type(v)
		if typ == "table" then
			calc_size(tbl, buf)
		elseif typ ~= "string" then
			v = tostring(v)
			tbl[i] = v
		end
		buf.size = buf.size + #v
	end
end

return {
	append = append,
	truncate = truncate,
	calc_size = calc_size,
}
