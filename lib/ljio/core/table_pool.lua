-- Copyright (C) Jinhua Luo

local M = {}
local _M = {}
local pool_mt = {__index=_M}

function _M.put(self, tbl)
	if self.n < self.max then
		tbl._next = self._next
		self._next = tbl
		self.n = self.n + 1
	end
end

function _M.get(self, ...)
	local tbl = self._next

	if tbl == nil then
		tbl = {}
		if self.mt then
			tbl = setmetatable(tbl, self.mt)
		end
	else
		self.n = self.n - 1
		self._next = tbl._next
		tbl._next = nil
		if self.clean then
			self.clean(tbl)
		end
	end

	for i = 1, select("#", ...) do
		tbl[i] = select(i, ...)
	end

	return tbl
end

local function clean_map(tbl)
	for k, v in pairs(tbl) do
		tbl[k] = nil
	end
end

local function clean_array(tbl)
	for i, v in ipairs(tbl) do
		tbl[i] = nil
	end
end

function M.new(clean, mt, max)
	return setmetatable({clean=clean, mt=mt, max=max or 100, n=0}, pool_mt)
end

function M.new_array(max)
	return M.new(clean_array, nil, max)
end

function M.new_map(max)
	return M.new(clean_map, nil, max)
end

return M
