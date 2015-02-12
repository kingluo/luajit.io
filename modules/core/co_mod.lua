local timer = require("core.timer_mod")
local add_timer = timer.add_timer

local co_idle_list = setmetatable({},{__mode="v"})
local co_info = {}

local function co_kill(co, parent)
	if co_info[co] then
		parent = parent or coroutine.running()
		if co_info[co].parent ~= parent then
			return false,'not direct child'
		end

		for child_co,_ in pairs(co_info[co].childs) do
			co_kill(child_co, co)
		end

		co_info[co] = nil
	end
	return true
end

local function co_resume(co, ...)
	local cinfo = co_info[co]
	if not cinfo then
		print"coroutine already killed"
		return false,"coroutine already killed"
	end

	local r,flag,data = coroutine.resume(co, ...)
	if coroutine.status(co) == "dead" then
		-- call gc first
		local gc = cinfo.gc
		if gc then gc() end

		-- tell parent
		local parent = cinfo.parent
		if parent then
			co_info[parent].childs[co] = nil
			if cinfo.wait_by_parent then
				co_resume(parent,r,flag,data)
			else
				co_info[parent].exit_childs[co] = {r,flag,data}
			end
		end

		-- kill all active childs
		for child_co,_ in pairs(cinfo.childs) do
			co_kill(child_co)
		end

		co_info[co] = nil
	end

	return r,flag,data
end

local epoll_hook_registered = false
local function co_yield_idle(flag, fd, ...)
	local co = coroutine.running()
	assert(co)

	if epoll_hook_registered == false then
		ep.add_prepare_hook(function()
			for i=1,#co_idle_list do
				co_resume(co_idle_list[1])
				table.remove(co_idle_list,1)
			end
			return ((#co_idle_list > 0) and 1 or -1)
		end)
		epoll_hook_registered = true
	end
	table.insert(co_idle_list, co)

	return coroutine.yield(flag, fd, ...)
end

local function co_yield(...)
	return coroutine.yield(...)
end

local function co_spawn(fn, gc)
	local parent = coroutine.running()
	local co = coroutine.create(function(...)
		-- make sandbox
		local G = {}
		G._G = G
		setmetatable(G, {__index = getfenv(0)})
		setfenv(0, G)
		setfenv(1, G)
		return fn(...)
	end)
	co_info[co] = {parent=parent, gc=gc,
		childs=setmetatable({},{__mode="k"}),
		exit_childs=setmetatable({},{__mode="k"})}
	if parent then co_info[parent].childs[co] = 1 end
	co_resume(co)
	return co
end

local function co_sleep(sec)
	local co = coroutine.running()
	assert(co)
	add_timer(function() co_resume(co) end, sec)
	co_yield()
end

local function co_wait(...)
	local parent = coroutine.running()
	assert(parent)
	local n = select('#',...)
	for i=1,n do
		local co = select(i,...)
		local d = co_info[parent].exit_childs[co]
		if d then
			co_info[parent].exit_childs[co] = nil
			return unpack(d)
		elseif not co_info[co] then
			return false,'#' .. i .. ': ' .. tostring(co) .. ' not exist'
		elseif co_info[co].parent ~= parent then
			return false,'#' .. i .. ': ' .. tostring(co) .. ' not your child'
		end
	end
	for i=1,n do
		local co = select(i,...)
		co_info[co].wait_by_parent = true
	end
	local r,flag,data = co_yield()
	for i=1,n do
		local co = select(i,...)
		if co_info[co] then
			co_info[co].wait_by_parent = false
		end
	end
	return r,flag,data
end

return {
	-- functions
	spawn = co_spawn,
	wait = co_wait,
	kill = co_kill,
	sleep = co_sleep,
	resume = co_resume,
	yield = co_yield,
	yield_idle = co_yield_idle,
}
