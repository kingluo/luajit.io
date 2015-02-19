local timer = require("core.timer")
local epoll = require("core.epoll")

local add_timer = timer.add_timer
local tinsert = table.insert
local tremove = table.remove

local coroutine_create = coroutine.create
local coroutine_resume = coroutine.resume
local coroutine_yield = coroutine.yield
local coroutine_running = coroutine.running
local coroutine_status = coroutine.status

local co_wait_list = setmetatable({},{__mode="k"})
local co_wait_list2 = setmetatable({},{__mode="k"})
local co_idle_list = setmetatable({},{__mode="v"})
local co_info = {}

local function handle_dead_co(co, ...)
	local cinfo = co_info[co]

	if cinfo.sleep_timer then
		cinfo.sleep_timer:cancel()
		cinfo.sleep_timer = nil
	end

	local gc = cinfo.gc
	if gc then gc() end

	local parent = cinfo.parent
	if parent then
		co_info[parent].exit_childs[co] = {...}
		if co_wait_list[parent] then
			co_wait_list[parent] = true
		end

		local ancestor = cinfo.ancestor
		if ancestor then
			ancestor = co_info[ancestor]
			if ancestor then
				ancestor.descendants = ancestor.descendants - 1
			end
		end
	end

	co_info[co] = nil
end

local function co_kill(co)
	if co_info[co] then
		if co_info[co].parent ~= coroutine_running() then
			return false,'not direct child'
		end

		handle_dead_co(co, false, "killed")
	end
	return true
end

local function co_resume_ll(co, propagate_err, ret, err, ...)
	if ret == false and propagate_err then
		error(err)
	end

	if coroutine_status(co) == "dead" then
		handle_dead_co(co, ret, err, ...)
	end

	return ret, err, ...
end

local function co_resume(co, ...)
	local cinfo = co_info[co]
	if not cinfo then return
		false,"coroutine dead"
	end

	return co_resume_ll(co, (cinfo.parent == nil),
		coroutine_resume(co, ...))
end

local epoll_idle_hook_registered = false
local function co_yield_idle(flag, ...)
	local co = coroutine_running()
	assert(co)

	if epoll_idle_hook_registered == false then
		epoll.add_prepare_hook(function()
			for i=1,#co_idle_list do
				co_resume(co_idle_list[1])
				tremove(co_idle_list,1)
			end
			return ((#co_idle_list > 0) and 1 or -1)
		end)
		epoll_idle_hook_registered = true
	end
	tinsert(co_idle_list, co)

	return coroutine_yield(flag, ...)
end

local function co_create(fn, gc)
	local parent = coroutine_running()

	local co = coroutine_create(function(...)
		-- make sandbox
		local G = {}
		G._G = G
		setmetatable(G, {__index = getfenv(0)})
		setfenv(0, G)
		setfenv(1, G)
		return fn(...)
	end)

	local cinfo = {
		parent = parent,
		gc = gc,
		exit_childs = setmetatable({},{__mode="k"})
	}

	co_info[co] = cinfo

	if parent then
		cinfo.ancestor = co_info[parent].ancestor or parent

		local ancestor = co_info[cinfo.ancestor]
		if ancestor then
			ancestor.descendants = ancestor.descendants + 1
		end
	else
		cinfo.descendants = 0
	end

	return co
end

local function co_spawn(fn, gc, ...)
	local co = co_create(fn, gc)
	local cr,err = co_resume(co, ...)
	if cr == false then
		error(err .. "\n" .. debug.traceback(co), 0)
	end
	return co
end

local function co_sleep(sec)
	local co = coroutine_running()
	assert(co)
	local cinfo = co_info[co]
	assert(cinfo)
	cinfo.sleep_timer = add_timer(
		function() cinfo.sleep_timer = nil; co_resume(co) end, sec)
	coroutine_yield()
end

local epoll_wait_hook_registered = false
local function co_wait(...)
	local parent = coroutine_running()
	assert(parent)
	local n = select('#',...)
	assert(n > 0)

	while true do
		for i=1,n do
			local co = select(i,...)
			local d = co_info[parent].exit_childs[co]
			if d then
				co_info[parent].exit_childs[co] = nil
				return unpack(d)
			elseif not co_info[co] then
				return false,'#' .. i .. ': ' .. tostring(co) .. ' not exist'
			elseif co_info[co].parent ~= parent then
				return false,'#' .. i .. ': ' .. tostring(co) .. ' not direct child'
			end
		end

		if epoll_wait_hook_registered == false then
			epoll.add_prepare_hook(function()
				for co,flag in pairs(co_wait_list) do
					if flag and co_info[co] then
						co_resume(co)
					end
				end
				return -1
			end)
			epoll_wait_hook_registered = true
		end

		co_wait_list[parent] = false
		coroutine_yield()
		co_wait_list[parent] = nil
	end
end

local epoll_wait_hook2_registered = false
local function wait_descendants()
	local co = coroutine.running()
	assert(co)
	local cinfo = co_info[co]
	assert(cinfo)
	if cinfo.descendants == nil or cinfo.descendants == 0 then
		return
	end

	if epoll_wait_hook2_registered == false then
		epoll.add_prepare_hook(function()
			for co in pairs(co_wait_list2) do
				local cinfo = co_info[co]
				if cinfo and cinfo.descendants == 0 then
					co_resume(co)
				end
			end
			return -1
		end)
		epoll_wait_hook2_registered = true
	end

	co_wait_list2[co] = 1
	coroutine_yield()
	co_wait_list2[co] = nil
end

local function co_wrap(fn, gc)
	local co = co_create(fn, gc)
	return function(...)
		if not co_info[co] then error("coroutine already killed") end
		return select(2, co_resume_ll(co, true, coroutine_resume(co, ...)))
	end
end

coroutine.create = co_create
coroutine.resume = co_resume
coroutine.wrap = co_wrap
coroutine.spawn = co_spawn
coroutine.wait = co_wait
coroutine.wait_descendants = wait_descendants
coroutine.kill = co_kill
coroutine.sleep = co_sleep
coroutine.yield_idle = co_yield_idle
