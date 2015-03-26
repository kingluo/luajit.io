-- Copyright (C) Jinhua Luo

local timer = require("ljio.core.timer")
local epoll = require("ljio.core.epoll")
local table_pool = require("ljio.core.table_pool")

local add_timer = timer.add_timer
local tinsert = table.insert
local tremove = table.remove

local coroutine_create = coroutine.create
local coroutine_resume = coroutine.resume
local coroutine_yield = coroutine.yield
local coroutine_running = coroutine.running
local coroutine_status = coroutine.status

local k_mode_mt = {__mode="k"}
local v_mode_mt = {__mode="v"}

local co_wait_list = setmetatable({}, k_mode_mt)
local co_wait_list2 = setmetatable({}, k_mode_mt)
local co_idle_list = setmetatable({}, v_mode_mt)
local co_info = {}

local co_mt = {__index = getfenv(0)}
local cinfo_pool = table_pool.new()

exit_vals_pool = table_pool.new_array()

local function kill_descendants(ancestor)
	for descendant in pairs(co_info[ancestor].descendants) do
		co_info[ancestor].descendants[descendant] = nil

		local cinfo = co_info[descendant]

		if cinfo.sleep_timer then
			cinfo.sleep_timer:cancel()
			cinfo.sleep_timer = nil
		end

		cinfo_pool:put(cinfo)
		co_info[descendant] = nil
	end

	co_info[ancestor].descendants_n = 0
end

local function handle_dead_co(co, ...)
	local cinfo = co_info[co]

	if cinfo.sleep_timer then
		cinfo.sleep_timer:cancel()
		cinfo.sleep_timer = nil
	end

	local parent = cinfo.parent
	if parent then
		if co_info[parent] then
			if co_info[parent].exit_childs == nil then
				co_info[parent].exit_childs = setmetatable({}, k_mode_mt)
			end
			co_info[parent].exit_childs[co] = exit_vals_pool:get(...)
			if co_wait_list[parent] == false then
				co_wait_list[parent] = true
			end
		end
		local ancestor = cinfo.ancestor
		if ancestor then
			ancestor = co_info[ancestor]
			if ancestor then
				ancestor.descendants[co] = nil
				ancestor.descendants_n = ancestor.descendants_n - 1
			end
		end
	else
		kill_descendants(co)
	end

	cinfo_pool:put(cinfo)
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

local function co_exit(exit_group)
	error(exit_group and "exit_group" or "exit", 0)
end

local function co_resume_ll(co, ret, ...)
	if ret == false then
		local err = ...
		if err == "exit_group" then
			local cur = coroutine.running()
			if cur == nil or co_info[cur].parent == nil then
				local ancestor = cur or co_info[co].ancestor or co
				handle_dead_co(co, ret, ...)
				kill_descendants(ancestor)
				return false, "exit_group"
			else
				error(err, 0)
			end
		end
	end

	if coroutine_status(co) == "dead" then
		handle_dead_co(co, ret, ...)
	end

	return ret, ...
end

local function co_resume(co, ...)
	if co_info[co] == nil then
		return false, "coroutine not exist"
	end

	return co_resume_ll(co, coroutine_resume(co, ...))
end

local epoll_idle_hook_registered = false
local function co_idle(flag, ...)
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

local function post_xpcall(gc, rc, ...)
	if gc then gc() end
	if rc == false then
		local err = ...
		if err == "exit_group" or err == "exit" then
			return error(err, 0)
		else
			return error(err)
		end
	end
	return ...
end

local function print_traceback(err)
	if err ~= "exit_group" and err ~= "exit" then
		print(debug.traceback(coroutine_running(), err, 2))
	end
	return err
end

local function co_create(fn, gc)
	local parent = coroutine_running()

	local co = coroutine_create(function(...)
		local G = {}
		G._G = G
		setmetatable(G, co_mt)
		setfenv(0, G)
		setfenv(1, G)
		return post_xpcall(gc, xpcall(fn, print_traceback, ...))
	end)

	local cinfo = cinfo_pool:get()
	cinfo.parent = parent
	cinfo.gc = gc
	cinfo.exit_childs = nil
	cinfo.ancestor = nil

	co_info[co] = cinfo

	if parent then
		cinfo.ancestor = co_info[parent].ancestor or parent
		local ancestor = co_info[cinfo.ancestor]
		ancestor.descendants[co] = 1
		ancestor.descendants_n = ancestor.descendants_n + 1
	else
		cinfo.descendants = setmetatable({}, k_mode_mt)
		cinfo.descendants_n = 0
	end

	return co
end

local function co_spawn(fn, gc, ...)
	local co = co_create(fn, gc)
	co_resume(co, ...)
	return co
end

local function co_sleep(sec)
	local co = coroutine_running()
	local cinfo = co_info[co]
	cinfo.sleep_timer = add_timer(function()
		cinfo.sleep_timer = nil; return co_resume(co) end, sec)
	return coroutine_yield()
end

local epoll_wait_hook_registered = false
local function co_wait(...)
	local parent = coroutine_running()
	assert(parent)
	local n = select('#', ...)
	assert(n > 0)

	while true do
		for i = 1, n do
			local co = select(i, ...)
			local vals = co_info[parent].exit_childs and co_info[parent].exit_childs[co] or nil
			if vals then
				exit_vals_pool:put(vals)
				co_info[parent].exit_childs[co] = nil
				return unpack(vals)
			elseif co_info[co] == nil then
				return false, '#' .. i .. ': ' .. tostring(co) .. ' not exist'
			elseif co_info[co].parent ~= parent then
				return false, '#' .. i .. ': ' .. tostring(co) .. ' not direct child'
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
	if cinfo.descendants == nil or cinfo.descendants_n == 0 then
		return
	end

	if epoll_wait_hook2_registered == false then
		epoll.add_prepare_hook(function()
			for co in pairs(co_wait_list2) do
				local cinfo = co_info[co]
				if cinfo and cinfo.descendants_n == 0 then
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
		return select(2, co_resume_ll(co, coroutine_resume(co, ...)))
	end
end

coroutine.create = co_create
coroutine.resume = co_resume
coroutine.wrap = co_wrap
coroutine.exit = co_exit
coroutine.spawn = co_spawn
coroutine.wait = co_wait
coroutine.wait_descendants = wait_descendants
coroutine.kill = co_kill
coroutine.sleep = co_sleep
coroutine.idle = co_idle
