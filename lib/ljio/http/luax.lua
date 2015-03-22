-- Copyright (C) Jinhua Luo

local bit = require("bit")
local C = require("ljio.cdef")
local inotify = require("ljio.core.inotify")

local strfind = string.find
local format = string.format
local strsub = string.sub

local tinsert = table.insert
local tconcat = table.concat

local luax_cache = {}

local function luax_compile(str)
	local codes = {"return function(req,rsp) "}
	local i = 1
	while true do
		local m = strfind(str,"<%",i,true)
		if m then
			if m ~= i then
				tinsert(codes, "rsp:print(")
				tinsert(codes, format("%q", strsub(str,i,m-1)))
				tinsert(codes, ");")
			end
			local n = strfind(str,"%>",m+2,true)
			if n == nil then
				error("syntax error")
			end
			i = n+2
			if strsub(str,m+2,m+2) == "=" then
				tinsert(codes, "rsp:print(")
				tinsert(codes, format("%s or ''", strsub(str,m+3,n-1)))
				tinsert(codes, ");")
			else
				tinsert(codes, format("%s;", strsub(str,m+2,n-1)))
			end
		else
			if i < #str then
				tinsert(codes, "rsp:print(")
				tinsert(codes, format("%q", strsub(str,i)))
				tinsert(codes, ");")
			end
			break
		end
	end
	tinsert(codes, " end")
	codes = tconcat(codes)
	return loadstring(codes)
end

local function readfile(path)
	local f = io.open(path)
	if f == nil then
		return nil, 404
	end
	local str = f:read('*a')
	f:close()
	if str == nil then
		return nil, 500
	end
	return str
end

local function service(req, rsp)
	local path = req.url.path
	if not luax_cache[path] then
		local fpath = {(req.lcf.root or "."), "", path}
		if req.lcf.luax_prefix then fpath[2] = req.lcf.luax_prefix end
		fpath = table.concat(fpath, "/")

		local str, code = readfile(fpath)
		if code then
			return rsp:finalize(code)
		end

		local err
		luax_cache[path],err = luax_compile(str)
		if err then print(err) end

		inotify.add_watch(fpath, function()
			local str = readfile(fpath)
			if str then
				local fn, err = luax_compile(str)
				if err == nil then
					luax_cache[path] = fn
				end
			end
		end, C.IN_MODIFY)
	end

	local fn = luax_cache[path]
	setfenv(fn, _G)
	fn = fn()
	return fn(req, rsp)
end

return service
