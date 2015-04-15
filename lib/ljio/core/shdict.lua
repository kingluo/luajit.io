-- Copyright (C) Jinhua Luo

local C = require("ljio.cdef")
local ffi = require("ffi")
local bit = require("bit")
local slab = require("ljio.core.slab")
local add_timer = require("ljio.core.timer").add_timer

local pthread = ffi.load("pthread")
local zlib = ffi.load("z")
local rt = ffi.load("rt")

local bor = bit.bor

local tconcat = table.concat
local tinsert = table.insert

local M = {}
local _M = {}
local shdict_mt = {__index = _M}

ffi.cdef[[
enum shdict_value_type {
    SHDICT_V_NUMBER,
    SHDICT_V_BOOL,
    SHDICT_V_STRING
};

typedef struct shdict_kv_s shdict_kv_t;
struct shdict_kv_s {
    unsigned char* key;
    size_t ksize;
    char typ;
    unsigned char* value;
    size_t vsize;
    shdict_kv_t* bprev;
    shdict_kv_t* bnext;
    shdict_kv_t* qprev;
    shdict_kv_t* qnext;
    struct timespec expire;
};

typedef struct shdict_s shdict_t;
struct shdict_s {
    pthread_rwlock_t lock;
    unsigned long size;
    unsigned long bsize;
    shdict_kv_t** buckets;
    shdict_kv_t* qhead;
    shdict_kv_t* qtail;
};
]]

local now = ffi.new("struct timespec")

local attr = ffi.new("pthread_rwlockattr_t")
assert(pthread.pthread_rwlockattr_init(attr) == 0)
assert(pthread.pthread_rwlockattr_setpshared(attr, C.PTHREAD_PROCESS_SHARED) == 0)

local hsize_sel = {3, 13, 23, 53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593,
    49157, 98317, 196613, 393241, 786433, 1572869, 3145739, 6291469,
    12582917, 25165843}
local hsize_sel_len = #hsize_sel

local expire_timer
local EXPIRE_INTERVAL = 3

local function validate_key(key)
    local typ = type(key)
    if typ == "number" then
        key = tostring(key)
    elseif typ ~= "string" then
        return nil
    end
    return key
end

local function lru_recycle(dict)
    pthread.pthread_rwlock_wrlock(dict.dict.lock)
    local kv =     dict.dict.qtail
    local count = 0
    while kv ~= nil and count < 10 do
        delete_ll(dict, kv)
        kv = kv.qprev
        count = count + 1
    end
    pthread.pthread_rwlock_unlock(dict.dict.lock)
end

local function slab_alloc(self, size, safe)
    local kv = slab.alloc(self.pool, size)
    if kv == nil and not safe then
        lru_recycle(self)
    end
    return slab.alloc(self.pool, size)
end

local function create_dict(name, size)
    local addr = C.mmap(nil, size, bor(C.PROT_READ, C.PROT_WRITE), bor(C.MAP_SHARED, C.MAP_ANON), -1, 0)
    assert(addr ~= -1)
    local pool = slab.pool_init(addr, size)
    local dict = ffi.cast("shdict_t*", slab.alloc(pool, ffi.sizeof("shdict_t")))
    C.memset(dict, 0, ffi.sizeof("shdict_t"))
    assert(pthread.pthread_rwlock_init(dict.lock, attr) == 0)
    dict.bsize = hsize_sel[1]
    local buckets_sz = dict.bsize * ffi.sizeof("shdict_kv_t*")
    dict.buckets = ffi.cast("shdict_kv_t**", slab.alloc(pool, buckets_sz))
    C.memset(dict.buckets, 0, buckets_sz)
    M.shared[name] = setmetatable({dict=dict, pool=pool, addr=addr, size=size}, shdict_mt)
end

local function key2bucket(dict, key, ksize)
    return tonumber(zlib.crc32(0, ffi.cast("Bytef*", key), ksize or #key)) % dict.bsize
end

local function time_le(a,b)
    if a.tv_sec <= b.tv_sec then
        return true
    end
    if a.tv_sec == b.tv_sec and a.tv_nsec <= b.tv_nsec then
        return true
    end
    return false
end

local function delete_ll(self, kv)
    if kv ~= nil then
        local dict = self.dict
        local pool = self.pool
        local idx = key2bucket(dict, kv.key, kv.ksize)
        if kv.bprev ~= nil then
            kv.bprev.bnext = kv.bnext
        end
        if kv.bnext ~= nil then
            kv.bnext.bprev = kv.bprev
        end
        if dict.buckets[idx] == kv then
            dict.buckets[idx] = kv.bnext
        end
        --#--
        if kv.qprev ~= nil then
            kv.qprev.qnext = kv.qnext
        end
        if kv.qnext ~= nil then
            kv.qnext.qprev = kv.qprev
        end
        if dict.qhead == kv then
            dict.qhead = kv.qnext
        end
        if dict.qtail == kv then
            dict.qtail = kv.qprev
        end
        --#--
        dict.size = dict.size - 1
        slab.free(pool, kv.key)
        slab.free(pool, kv.value)
        slab.free(pool, kv)
    end
end

local function expire_handler()
    rt.clock_gettime(C.CLOCK_MONOTONIC_RAW, now)
    for name,dict in pairs(M.shared) do
        pthread.pthread_rwlock_wrlock(dict.dict.lock)
        local kv =     dict.dict.qtail
        local count = 0
        while kv ~= nil and count < 20 do
            if kv.expire.tv_sec > 0 then
                if time_le(kv.expire, now) then
                    print("remove expired key=" .. ffi.string(kv.key, kv.ksize))
                    delete_ll(dict, kv)
                end
            end
            kv = kv.qprev
            count = count + 1
        end
        pthread.pthread_rwlock_unlock(dict.dict.lock)
    end
    add_timer(expire_handler, EXPIRE_INTERVAL)
end

function M.init(cfg)
    if M.shared then
        for name,dict in pairs(M.shared) do
            print("munmap " .. name)
            assert(C.munmap(dict.addr, dict.size) == 0)
        end
    end
    if cfg.lua_shared_dict then
        M.shared = {}
        for name,size in pairs(cfg.lua_shared_dict) do
            local size, unit = string.match(size, "(%d+)([km])")
            assert(size and unit)
            if unit == "k" then
                size = size * 1024
            else
                size = size * 1024 * 1024
            end
            create_dict(name, size)
        end
        if expire_timer == nil then
            expire_timer = add_timer(expire_handler, EXPIRE_INTERVAL)
        end
    end
end

local function find_key(dict, key)
    local ksize = #key
    local bucket =     dict.buckets[key2bucket(dict, key)]
    while bucket ~= nil do
        if ksize == bucket.ksize and C.memcmp(bucket.key, key, ksize) == 0 then
            return bucket
        end
        bucket = bucket.bnext
    end
end

local function write_value(self, bucket, value, safe)
    local typ = type(value)
    if typ == "boolean" then
        bucket.typ = C.SHDICT_V_BOOL
        value = tostring(value)
    elseif typ == "number" then
        bucket.typ = C.SHDICT_V_NUMBER
        value = tostring(value)
    elseif typ == "string" then
        bucket.typ = C.SHDICT_V_STRING
    else
        bucket.typ = C.SHDICT_V_STRING
        value = tostring(value)
    end
    if bucket.value ~= nil then
        slab.free(self.pool, bucket.value)
    end
    bucket.vsize = #value
    bucket.value = slab_alloc(self, #value, safe)
    if bucket.value == nil then
        return false, "no memory"
    end
    ffi.copy(bucket.value, value, #value)
end

local function rehash(self, safe)
    local dict = self.dict
    local newsize = dict.size + 1
    if newsize < dict.bsize or newsize >= hsize_sel[hsize_sel_len] then
        return
    end

    local newbsize
    for i=1,hsize_sel_len do
        if newsize < hsize_sel[i] then
            newbsize = hsize_sel[i]
            break
        end
    end

    local pool = self.pool
    local newb = slab_alloc(self, newbsize * ffi.sizeof("shdict_kv_t*"), safe)
    if newb == nil then
        return false, "no memory"
    end

    slab.free(pool, dict.buckets)
    dict.buckets = ffi.cast("shdict_kv_t**", newb)
    C.memset(dict.buckets, 0, newbsize * ffi.sizeof("shdict_kv_t*"))
    dict.bsize = newbsize

    local kv =     dict.qtail
    while kv ~= nil do
        local idx = key2bucket(dict, kv.key, kv.ksize)
        local bucket = dict.buckets[idx]
        dict.buckets[idx] = kv
        kv.bprev = nil
        kv.bnext = nil
        if bucket ~= nil then
            bucket.bprev = kv
            kv.bnext = bucket
        end
        kv = kv.qprev
    end
end

local function add_key(self, key, exptime, safe)
    rehash(self, safe)
    local kv = ffi.cast("shdict_kv_t*", slab_alloc(self, ffi.sizeof("shdict_kv_t"), safe))
    if kv == nil then
        return false, "no memory"
    end
    C.memset(kv, 0, ffi.sizeof("shdict_kv_t"))
    if exptime and exptime > 0 then
        rt.clock_gettime(C.CLOCK_MONOTONIC_RAW, kv.expire)
        kv.expire.tv_sec = kv.expire.tv_sec + math.floor(exptime)
        kv.expire.tv_nsec = kv.expire.tv_nsec + (exptime%1) * 1000 * 1000 * 1000
    end
    kv.key = slab_alloc(self, #key, safe)
    if kv == nil then
        slab.free(self.pool, kv)
        return false, "no memory"
    end
    ffi.copy(kv.key, key, #key)
    kv.ksize = #key
    --#--
    local dict = self.dict
    local idx = key2bucket(dict, key)
    local bucket = dict.buckets[idx]
    dict.buckets[idx] = kv
    if bucket ~= nil then
        bucket.bprev = kv
        kv.bnext = bucket
    end
    --#--
    if dict.qhead ~= nil then
        dict.qhead.qprev = kv
        kv.qnext = dict.qhead
        dict.qhead = kv
    else
        dict.qhead = kv
        dict.qtail = kv
    end
    --#--
    dict.size = dict.size + 1
    return kv
end

local function set_ll(self, key, value, exptime, op, safe)
    key = validate_key(key)
    if key == nil then return false, "key type must be string or number" end

    local dict = self.dict

    pthread.pthread_rwlock_wrlock(dict.lock)

    local kv = find_key(dict, key)
    if kv == nil then
        if op == "replace" or op == "incr" then
            return false, "not found"
        end
        if op == "set" then
            op = "add"
        end
        kv = add_key(self, key, exptime, safe)
    elseif op == "add" then
        return false, "exists"
    end

    if op == "incr" then
        if kv.typ ~= C.SHDICT_V_NUMBER then
            return nil, "not a number"
        end
        value = tonumber(ffi.string(kv.value, kv.vsize)) + value
    end

    write_value(self, kv, value, safe)

    if op == "set" or op == "incr" or op == "replace" then
        if dict.qhead ~= nil and dict.qhead ~= kv then
            dict.qhead.qprev = kv
            kv.qnext = dict.qhead
            dict.qhead = kv
        end
    end

    pthread.pthread_rwlock_unlock(dict.lock)

    return (op ~= "incr") and true or value
end

function _M.delete(self, key)
    key = validate_key(key)
    if key == nil then return false, "key type must be string or number" end

    local dict = self.dict
    pthread.pthread_rwlock_wrlock(dict.lock)

    delete_ll(self, find_key(dict, key))

    pthread.pthread_rwlock_unlock(dict.lock)
    return true
end

function _M.set(self, key, value, exptime)
    if value == nil then
        return self:delete(key)
    end
    return set_ll(self, key, value, exptime, "set")
end

function _M.safe_set(self, key, value, exptime)
    return set_ll(self, key, value, exptime, "set", true)
end

function _M.add(self, key, value, exptime)
    return set_ll(self, key, value, exptime, "add")
end

function _M.safe_add(self, key, value, exptime)
    return set_ll(self, key, value, exptime, "add", true)
end

function _M.replace(self, key, value, exptime)
    return set_ll(self, key, value, exptime, "replace")
end

function _M.incr(self, key, value)
    return set_ll(self, key, value, nil, "incr")
end

function _M.flush_all(self)
    local dict = self.dict
    local pool = self.pool
    pthread.pthread_rwlock_wrlock(dict.lock)
    local kv =     dict.qtail
    while kv ~= nil do
        slab.free(pool, kv.key)
        slab.free(pool, kv.value)
        slab.free(pool, kv)
        kv = kv.qprev
    end
    dict.size = 0
    C.memset(dict.buckets, 0, dict.bsize * ffi.sizeof("shdict_kv_t*"))
    dict.qhead = nil
    dict.qtail = nil
    pthread.pthread_rwlock_unlock(dict.lock)
end

function _M.get(self, key)
    key = validate_key(key)
    if key == nil then return false, "key type must be string or number" end
    local value
    local dict = self.dict
    pthread.pthread_rwlock_rdlock(dict.lock)

    local kv = find_key(dict, key)
    if kv ~= nil then
        if kv.expire.tv_sec > 0 then
            rt.clock_gettime(C.CLOCK_MONOTONIC_RAW, now)
            if time_le(kv.expire, now) then
                delete_ll(self, kv)
                pthread.pthread_rwlock_unlock(dict.lock)
                return nil, "expired"
            end
        end
        value = ffi.string(kv.value, kv.vsize)
        if kv.typ == C.SHDICT_V_BOOL then
            value = (value == "true")
        elseif kv.typ == C.SHDICT_V_NUMBER then
            value = tonumber(value)
        end

        if dict.qhead ~= kv then
            if kv.qprev ~= nil then
                kv.qprev.qnext = kv.qnext
            end
            if kv.qnext ~= nil then
                kv.qnext.qprev = kv.qprev
            end
            kv.qnext = dict.qhead
            dict.qhead = kv
            if dict.qtail == kv then
                dict.qtail = kv.qprev
            end
        end
    end

    pthread.pthread_rwlock_unlock(dict.lock)
    return value
end

function _M.get_keys(self, max_count)
    max_count = max_count or 1024
    if max_count == 0 then max_count = nil end
    local t = {}
    local dict = self.dict
    pthread.pthread_rwlock_rdlock(dict.lock)
    local kv =     dict.qhead
    while kv ~= nil do
        tinsert(t, ffi.string(kv.key, kv.ksize))
        if max_count then
            max_count = max_count - 1
            if max_count == 0 then break end
        end
        kv = kv.qnext
    end
    pthread.pthread_rwlock_unlock(dict.lock)
    return t
end

return M
