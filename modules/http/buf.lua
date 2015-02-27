local function calc_size(v)
	local size = 0
	local typ = type(v)
	if typ == "table" then
		for i,v2 in ipairs(v) do
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
	return v,size
end

local buf_mt = {__index={}}

function buf_mt.__index.append(self, ...)
	for i = 1,select("#", ...) do
		self._n = self._n + 1
		local v,sz = calc_size(select(i, ...))
		self[self._n] = v
		self.size = self.size + sz
	end
end

function buf_mt.__index.swap(self, ...)
	local n = select("#", ...)
	for i = n+1, self._n do
		self[i] = nil
	end
	self._n = 0
	self.size = 0
	return self:append(...)
end

local bufpool_mt = {__index={}}

function bufpool_mt.__index.get(self, ...)
	local buf = self._next
	if buf == nil then
		buf = setmetatable({_n=0,size=0}, buf_mt)
	else
		self.n_buf = self.n_buf - 1
		self._next = buf._next
		buf._next = nil
	end
	buf:swap(...)
	return buf
end

function bufpool_mt.__index.put(self, buf)
	if self.n_buf < self.max then
		for k in pairs(buf) do
			buf[k] = nil
		end
		buf._n = #buf
		buf._next = self._next
		self._next = buf
		self.n_buf = self.n_buf + 1
	end
end

return function(max)
	return setmetatable({max=max,n_buf=0}, bufpool_mt)
end
