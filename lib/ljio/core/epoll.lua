-- Copyright (C) Jinhua Luo

local ffi = require("ffi")
local C = require("ljio.cdef")
local bit = require("bit")
local utils = require("ljio.core.utils")

local g_epoll_fd
local g_prepare_hooks
local handlers

local MAX_EPOLL_EVENT = 128
local ev_set = ffi.new("struct epoll_event[?]", MAX_EPOLL_EVENT)
local ev_c = ffi.new("struct epoll_event")

local function add_event(ev, ...)
    handlers[ev.fd] = ev
    local cmd
    if not ev.events then
        ev.events = 0
        cmd = C.EPOLL_CTL_ADD
    else
        cmd = C.EPOLL_CTL_MOD
    end
    if bit.band(ev.events, ...) == 0 then
        ev_c.data.fd = ev.fd
        ev_c.events = bit.bor(ev.events, ...)
        ev.events = ev_c.events
        assert(C.epoll_ctl(g_epoll_fd, cmd, ev.fd, ev_c) == 0)
    end
end

local function del_event(ev, ...)
    if not handlers[ev.fd] then return end
    local n_event = select('#',...)
    if n_event == 0 then
        assert(handlers[ev.fd] == ev)
        assert(C.epoll_ctl(g_epoll_fd, C.EPOLL_CTL_DEL, ev.fd, nil) == 0)
        handlers[ev.fd] = nil
        ev.events = nil
    else
        ev_c.data.fd = ev.fd
        ev_c.events = bit.band(ev.events, bit.bnot(bit.bor(...)))
        ev.events = ev_c.events
        assert(C.epoll_ctl(g_epoll_fd, C.EPOLL_CTL_MOD, ev.fd, ev_c) == 0)
    end
end

local function init(epoll_size)
    if g_epoll_fd then
        assert(C.close(g_epoll_fd) == 0)
    end
    g_epoll_fd = C.epoll_create(epoll_size or 20000)
    g_prepare_hooks = {}
    handlers = setmetatable({},{__mode="v"})
end

local function add_prepare_hook(hook)
    table.insert(g_prepare_hooks, hook)
end

local function run(expect_events)
    assert((expect_events == nil) or (expect_events >= 0))
    local n_events = 0
    while true do
        local wait_timeout = -1
        local to_exit = false
        for _,hook in ipairs(g_prepare_hooks) do
            local t
            t,to_exit = hook()
            if to_exit == true then return n_events end
            if t and t >= 0 then
                if wait_timeout == -1 or t < wait_timeout then
                    wait_timeout = t
                end
            end
        end

        -- print("# pid=" .. C.getpid() .. " epoll_wait enter...")
        local n = C.epoll_wait(g_epoll_fd, ev_set, MAX_EPOLL_EVENT, wait_timeout)
        -- print("# pid=" .. C.getpid() .. " epoll_wait exit...")

        if n == -1 then return n_events, utils.strerror() end

        if n > 0 then
            for ev_idx = 0, n-1 do
                local fd = ev_set[ev_idx].data.fd
                n_events = n_events + 1
                assert(handlers[fd])
                handlers[fd].handler(handlers[fd], ev_set[ev_idx].events)
            end
        end

        if expect_events and n_events >= expect_events then
            return n_events
        end
    end
end

return {
    add_event = add_event,
    del_event = del_event,
    add_prepare_hook = add_prepare_hook,
    init = init,
    run = run,
}
