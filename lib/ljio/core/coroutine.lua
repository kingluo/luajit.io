-- Copyright (C) Jinhua Luo

local ffi = require("ffi")
local timer = require("ljio.core.timer")
local epoll = require("ljio.core.epoll")
local add_timer = timer.add_timer
local pairs = pairs

local coroutine_create = coroutine.create
local coroutine_resume = coroutine.resume
local coroutine_yield = coroutine.yield
local coroutine_running = coroutine.running
local coroutine_status = coroutine.status

local co_wait_list = {}
local co_wait_list2 = {}
local co_idle_list = {}
local co_info = {}

local function remove_co(co)
	local cinfo = co_info[co]

	if cinfo.sleep_timer then
		cinfo.sleep_timer:cancel()
		cinfo.sleep_timer = nil
	end

	co_wait_list[co] = nil
	co_wait_list2[co] = nil
	co_idle_list[co] = nil

	co_info[co] = nil
end

local function kill_descendants(ancestor)
	for descendant in pairs(co_info[ancestor].descendants) do
		co_info[ancestor].descendants[descendant] = nil
		remove_co(descendant)
	end

	co_info[ancestor].descendants_n = 0
end

local function handle_dead_co(co, ...)
	local cinfo = co_info[co]

	local parent = cinfo.parent
	if parent then
		if co_info[parent] then
			if co_info[parent].exit_childs == nil then
				co_info[parent].exit_childs = {}
			end
			co_info[parent].exit_childs[co] = {...}
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
	elseif cinfo.descendants then
		kill_descendants(co)
	end

	return remove_co(co)
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
		elseif err ~= "exit" and err ~= nil then
			print(debug.traceback(co, err))
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

local function idle_handler()
	for co in pairs(co_idle_list) do
		co_idle_list[co] = nil
		co_resume(co)
	end
	local ret = -1
	for co in pairs(co_idle_list) do
		ret = 0
		break
	end
	return ret
end

local epoll_idle_hook_registered = false
local function co_idle()
	local co = coroutine_running()
	co_idle_list[co] = 1

	if epoll_idle_hook_registered == false then
		epoll.add_prepare_hook(idle_handler)
		epoll_idle_hook_registered = true
	end

	return coroutine_yield()
end

local function wrap_fn(fn, gc)
	return function(...)
		local ret = {xpcall(fn, function(err)
			if err ~= "exit" or err ~= "exit_group" then
				print(debug.traceback(err, 2))
			else
				return err
			end
		end, ...)}
		gc(ret)
		if ret[1] == false then
			error(ret[2])
		end
		return unpack(ret, 2)
	end
end

local function co_create(fn, gc)
	local parent = coroutine_running()

	local co = coroutine_create(gc and wrap_fn(fn, gc) or fn)

	local cinfo = {parent = parent}

	co_info[co] = cinfo

	if parent then
		cinfo.ancestor = co_info[parent].ancestor or parent
		local ancestor = co_info[cinfo.ancestor]
		if ancestor.descendants == nil then
			ancestor.descendants = {}
			ancestor.descendants_n = 0
		end
		ancestor.descendants[co] = 1
		ancestor.descendants_n = ancestor.descendants_n + 1
	end

	return co
end

local function co_sleep(sec)
	local co = coroutine_running()
	local cinfo = co_info[co]
	cinfo.sleep_timer = add_timer(function()
		cinfo.sleep_timer = nil; return co_resume(co) end, sec)
	return coroutine_yield()
end


local function wait_handler()
	for co,flag in pairs(co_wait_list) do
		if flag and co_info[co] then
			co_resume(co)
		end
	end
	return -1
end

local epoll_wait_hook_registered = false
local function co_wait(...)
	local parent = coroutine_running()
	assert(parent)
	local n = select('#', ...)
	assert(n > 0)

	--while true do
		for i = 1, n do
			local co = select(i, ...)
			local vals = co_info[parent].exit_childs and co_info[parent].exit_childs[co] or nil
			if vals then
				co_info[parent].exit_childs[co] = nil
				return unpack(vals)
			elseif co_info[co] == nil then
				return false, '#' .. i .. ': ' .. tostring(co) .. ' not exist'
			elseif co_info[co].parent ~= parent then
				return false, '#' .. i .. ': ' .. tostring(co) .. ' not direct child'
			end
		end

		if epoll_wait_hook_registered == false then
			epoll.add_prepare_hook(wait_handler)
			epoll_wait_hook_registered = true
		end

		co_wait_list[parent] = false
		coroutine_yield()
		co_wait_list[parent] = nil
		return co_wait(...)
	--end
end

local function wait2_handler()
	for co in pairs(co_wait_list2) do
		local cinfo = co_info[co]
		if cinfo and cinfo.descendants_n == 0 then
			co_resume(co)
		end
	end
	return -1
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
		epoll.add_prepare_hook(wait2_handler)
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
coroutine.wait = co_wait
coroutine.wait_descendants = wait_descendants
coroutine.kill = co_kill
coroutine.sleep = co_sleep
coroutine.idle = co_idle

-- local function test()
	-- return 1, 2, 3
-- end

-- local total = 0
-- for i = 1, 5000000 do
	-- local co = coroutine.create(test)
	-- local ret, v = coroutine.resume(co)
	-- total = total + v
-- end
-- print(total)
