local C = require("cdef")
local ffi = require("ffi")
local bit = require("bit")
local slab = require("core.slab")

local pthread = ffi.load("pthread")
local zlib = ffi.load("z")

local bor = bit.bor

local tconcat = table.concat
local tinsert = table.insert

local dict_list = {}
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
	size_t vsize;
	unsigned char* value;
	shdict_kv_t* bprev;
	shdict_kv_t* bnext;
	shdict_kv_t* qprev;
	shdict_kv_t* qnext;
	struct itimerspec expire;
};

typedef struct shdict_s shdict_t;
struct shdict_s {
	pthread_rwlock_t lock;
	unsigned long size;
	unsigned long bsize;
	shdict_kv_t** buckets;
	shdict_kv_t* queue;
};
]]

local attr = ffi.new("pthread_rwlockattr_t")
assert(pthread.pthread_rwlockattr_init(attr) == 0)
assert(pthread.pthread_rwlockattr_setpshared(attr, C.PTHREAD_PROCESS_SHARED) == 0)

local hsize_sel = {3, 13, 23, 53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593,
	49157, 98317, 196613, 393241, 786433, 1572869, 3145739, 6291469,
	12582917, 25165843}
local hsize_sel_len = #hsize_sel

local function create_dict(name, size)
	local addr = C.mmap(nil, size, bor(C.PROT_READ, C.PROT_WRITE), bor(C.MAP_SHARED, C.MAP_ANON), -1, 0)
	assert(addr ~= -1)
	local pool = slab.pool_init(addr, size)
	local dict = ffi.cast("shdict_t*", slab.alloc(pool, ffi.sizeof("shdict_t")))
	assert(pthread.pthread_rwlock_init(dict.lock, attr) == 0)
	dict.size = 0
	dict.bsize = hsize_sel[1]
	dict.buckets = ffi.cast("shdict_kv_t**", slab.alloc(pool, dict.bsize * ffi.sizeof("shdict_kv_t*")))
	for i=0,dict.bsize-1 do
		dict.buckets[i] = nil
	end
	dict.queue = nil
	dict_list[name] = setmetatable({dict=dict, pool=pool}, shdict_mt)
end

local function init(cfg)
	if cfg.lua_shared_dict then
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
	end
end

local function key2bucket(dict, key)
	return tonumber(zlib.crc32(0, ffi.cast("Bytef*", key), #key)) % dict.bsize
end

local function find_key(dict, key)
	local bucket = 	dict.buckets[key2bucket(dict, key)]
	while bucket ~= nil do
		if C.memcmp(bucket.key, key, bucket.ksize) == 0 then
			return bucket
		end
		bucket = bucket.bnext
	end
end

local function write_value(self, bucket, value)
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
	bucket.value = slab.alloc(self.pool, #value)
	ffi.copy(bucket.value, value, #value)
end

local function rehash(self)
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
	local newb = slab.alloc(pool, newbsize * ffi.sizeof("shdict_kv_t*"))
	ffi.copy(newb, dict.buckets, dict.bsize * ffi.sizeof("shdict_kv_t*"))
	slab.free(pool, dict.buckets)
	dict.buckets = newb
	dict.bsize = newbsize
end

local function add_key(self, key)
	rehash(self)
	local kv = ffi.cast("shdict_kv_t*", slab.alloc(self.pool, ffi.sizeof("shdict_kv_t")))
	kv.key = slab.alloc(self.pool, #key)
	ffi.copy(kv.key, key, #key)
	kv.ksize = #key
	kv.value = nil
	--#--
	local dict = self.dict
	local idx = key2bucket(dict, key)
	local bucket = dict.buckets[idx]
	dict.buckets[idx] = kv
	kv.bnext = nil
	kv.bprev = nil
	if bucket ~= nil then
		bucket.bprev = kv
		kv.bnext = bucket
	end
	--#--
	kv.qnext = nil
	kv.qprev = nil
	local queue = dict.queue
	dict.queue = kv
	if queue ~= nil then
		queue.qprev = kv
		kv.qnext = queue
	end
	--#--
	dict.size = dict.size + 1
	return kv
end

function _M.set(self, key, value)
	local dict = self.dict
	pthread.pthread_rwlock_wrlock(dict.lock)

	local kv = find_key(dict, key)
	if kv == nil then
		kv = add_key(self, key)
	end

	write_value(self, kv, value)
	pthread.pthread_rwlock_unlock(dict.lock)
	return true
end

function _M.add(self, key, value)
	local dict = self.dict
	pthread.pthread_rwlock_wrlock(dict.lock)

	local kv = find_key(dict, key)
	if kv == nil then
		kv = add_key(self, key)
		write_value(self, kv, value)
	end

	pthread.pthread_rwlock_unlock(dict.lock)
	return true
end

function _M.delete(self, key)
	local dict = self.dict
	pthread.pthread_rwlock_wrlock(dict.lock)

	local kv = find_key(dict, key)
	if kv ~= nil then
		if kv.bprev == nil then
			dict.buckets[key2bucket(dict, key)] = nil
		else
			kv.bprev.bnext = kv.bnext
		end
		if kv.bnext ~= nil then
			kv.bnext.bprev = kv.bprev
		end
		--#--
		if kv.qprev == nil then
			dict.queue = nil
		else
			kv.qprev.qnext = kv.qnext
		end
		if kv.qnext ~= nil then
			kv.qnext.qprev = kv.qprev
		end
		--#--
		dict.size = dict.size - 1
		slab.free(self.pool, kv.key)
		slab.free(self.pool, kv.value)
		slab.free(self.pool, kv)
	end

	pthread.pthread_rwlock_unlock(dict.lock)
	return true
end

function _M.get(self, key)
	local value
	local dict = self.dict
	pthread.pthread_rwlock_rdlock(dict.lock)

	local kv = find_key(dict, key)
	if kv ~= nil then
		value = ffi.string(kv.value, kv.vsize)
		if kv.typ == C.SHDICT_V_BOOL then
			value = (value == "true")
		elseif kv.typ == C.SHDICT_V_NUMBER then
			value = tonumber(value)
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
	local kv = 	dict.queue
	while kv ~= nil do
		tinsert(t, ffi.string(kv.key, kv.ksize))
		if max_count then
			max_count = max_count - 1
			if max_count == 0 then break end
		end
		kv = kv.bnext
	end
	pthread.pthread_rwlock_unlock(dict.lock)
	return unpack(t)
end

return {
	init = init,
	shared = dict_list
}
