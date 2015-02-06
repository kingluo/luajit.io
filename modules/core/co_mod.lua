local timer = require("core.timer_mod")
local add_timer = timer.add_timer

-- coroutine yield flag
local YIELD_IO = 1
local YIELD_SLEEP = 2
local YIELD_IDLE = 3
local YIELD_WAIT = 4
local YIELD_DNS = 5

local co_wait_io_list = {}
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

local function co_yield(flag, fd, ...)
	local co = coroutine.running()
	assert(co)

	if flag == YIELD_IO then
		if not co_wait_io_list[fd] then
			co_wait_io_list[fd] = setmetatable({},{__mode="v"})
		end
		table.insert(co_wait_io_list[fd], co)
	elseif flag == YIELD_IDLE then
		table.insert(co_idle_list, co)
	end

	return coroutine.yield(flag, fd, ...)
end

local function co_spawn(fn, gc)
	local parent = coroutine.running()
	local co = coroutine.create(fn)
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
	co_yield(YIELD_SLEEP)
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
	local r,flag,data = co_yield(YIELD_WAIT)
	for i=1,n do
		local co = select(i,...)
		if co_info[co] then
			co_info[co].wait_by_parent = false
		end
	end
	return r,flag,data
end

local function resume_wait_io_list(fd)
	local co_list = co_wait_io_list[fd]
	local n_co = 0
	if co_list then
		n_co = #co_list
		for i=1,n_co do
			co_resume(co_list[1])
			table.remove(co_list,1)
		end
	end
	return n_co
end

local function resume_idle_list()
	for i=1,#co_idle_list do
		co_resume(co_idle_list[1])
		table.remove(co_idle_list,1)
	end
	return #co_idle_list
end

return {
	-- functions
	resume_idle_list = resume_idle_list,
	resume_wait_io_list = resume_wait_io_list,
	spawn = co_spawn,
	wait = co_wait,
	kill = co_kill,
	sleep = co_sleep,
	resume = co_resume,
	yield = co_yield,
	-- constants
	YIELD_IO = YIELD_IO,
	YIELD_SLEEP = YIELD_SLEEP,
	YIELD_IDLE = YIELD_IDLE,
	YIELD_WAIT = YIELD_WAIT,
	YIELD_DNS = YIELD_DNS,
}
