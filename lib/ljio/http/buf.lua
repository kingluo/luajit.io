-- Copyright (C) Jinhua Luo

local function calc_size(v)
	local size = 0
	local typ = type(v)
	if typ == "table" then
		for i, v2 in ipairs(v) do
			local sz
			v2, sz = calc_size(v2)
			size = size + sz
			v[i] = v2
		end
	else
		if typ ~= "string" then
			v = tostring(v)
		end
		size = size + #v
	end
	return v, size
end

local buf_mt = {__index={}}

function buf_mt.__index.append(self, vv, ...)
	--for i = 1, select("#", ...) do
		--local vv = select(i, ...)
		if vv then
		local v, sz = calc_size(vv)
		table.insert(self, v)
		self.size = self.size + sz
	--end
	if select("#",...) > 0 then
		return self:append(...)
	end
end
end

local bufpool_mt = {__index={}}

function bufpool_mt.__index.get(self, ...)
	local buf = setmetatable({size = 0}, buf_mt)
	buf:append(...)
	return buf
end

return function(max)
	return setmetatable({max=max,n_buf=0}, bufpool_mt)
end
