-- Copyright (C) Jinhua Luo

local ffi = require("ffi")
local C = require("ljio.cdef")

local pthread = ffi.load("pthread")

local bit = require("bit")
local band = bit.band
local bor = bit.bor
local bnot = bit.bnot
local lshift = bit.lshift
local rshift = bit.rshift

local ceil = math.ceil
local floor = math.floor

ffi.cdef[[
static const int SLAB_MINSHIFT = 3;
static const int SLAB_MAXSHIFT = 11;
static const int SLAB_N_SLOTS = SLAB_MAXSHIFT - SLAB_MINSHIFT + 1;

typedef struct slab_page_s slab_page_t;
struct slab_page_s {
	uint32_t slab;
	slab_page_t* next;
	slab_page_t* prev;
};

typedef struct slab_pool_s slab_pool_t;
struct slab_pool_s {
	pthread_mutex_t mutex;
	slab_page_t* pages;
	slab_page_t free;
	unsigned char* addr;
	unsigned char* start;
	unsigned char* endp;
	slab_page_t slots[SLAB_N_SLOTS];
};
]]

local SLAB_PAGE = 0
local SLAB_SMALL = 1
local SLAB_EXACT = 2
local SLAB_BIG = 3

local MAX_SIZE = lshift(1, C.SLAB_MAXSHIFT)
local EXACT_SIZE = lshift(1, 7)
local PAGE_SIZE = 4096
local PAGE_ALIGN = bnot(PAGE_SIZE - 1)
local slab_pool_sz = ffi.sizeof("slab_pool_t")
local slab_page_sz = ffi.sizeof("slab_page_t")
local uintptr_sz = ffi.sizeof("uintptr_t")
local uintptr_max = ffi.cast("uintptr_t", -1)

local attr = ffi.new("pthread_mutexattr_t")
assert(pthread.pthread_mutexattr_init(attr) == 0)
assert(pthread.pthread_mutexattr_setpshared(attr, C.PTHREAD_PROCESS_SHARED) == 0)

local function slab_pool_init(pool, size)
	local addr = ffi.cast("unsigned char*", pool)
	C.memset(addr, 0, size)
	pool = ffi.cast("slab_pool_t*", pool)
	pool.addr = addr

	assert(pthread.pthread_mutex_init(pool.mutex, attr) == 0)

	size = band(size, PAGE_ALIGN)
	pool.endp = ffi.cast("unsigned char*", addr + size)
	pool.pages = ffi.cast("slab_page_t*", addr + slab_pool_sz)

	local n_pages = floor((size - slab_pool_sz) / (PAGE_SIZE + slab_page_sz))
	addr = ffi.cast("uintptr_t", addr + slab_pool_sz + n_pages * slab_page_sz + PAGE_SIZE - 1)
	local s = ffi.cast("uintptr_t", addr / PAGE_SIZE * PAGE_SIZE)
	pool.start = ffi.cast("unsigned char*", s)
	assert(n_pages == (pool.endp - pool.start) / PAGE_SIZE)

	local page = pool.pages[0]
	local tail = pool.pages[n_pages-1]

	page.slab = n_pages
	page.next = pool.free
	page.prev = pool.free

	pool.free.slab = n_pages
	pool.free.next = page
	pool.free.prev = page

	tail.slab = n_pages

	for i=0, C.SLAB_N_SLOTS-1 do
		local slot = pool.slots[i]
		slot.slab = lshift(1, C.SLAB_MINSHIFT + i)
		slot.prev = slot
		slot.next = slot
	end

	return pool
end

local function alloc_pages(pool, n_pages)
	local page = pool.free.next
	while page ~= pool.free do
		if page.slab >= n_pages then
			local left = page.slab - n_pages
			if left > 0 then
				page.slab = n_pages
				local page2 = page + n_pages
				page2.slab = left
				page2.prev = page.prev
				page.prev.next = page2
				page2.next = page.next
				page.next.prev = page2
				if left > 1 then
					local tail = page2 + left - 1
					tail.slab = left
					tail.prev = nil
					tail.next = nil
				end
			end
			page.prev = nil
			page.next = nil
			if n_pages > 1 then
				local tail = page + n_pages - 1
				tail.slab = n_pages
				tail.prev = nil
				tail.next = nil
			end
			return page
		end
		page = page.next
	end
end

local function free_pages(pool, n_page)
	local page = pool.pages + n_page
	if n_page + page.slab < pool.free.slab then
		local page2 = page + page.slab
		if page2.next ~= nil and ffi.cast("uintptr_t", page2.prev) % 4 == SLAB_PAGE then
			page.slab = page.slab + page2.slab
			page.prev = page2.prev
			page2.prev.next = page
			page.next = page2.next
			page2.next.prev = page
			--#--
			page2.slab = 0
			page2.prev = nil
			page2.next = nil
			--#--
			local tail = page + page.slab - 1
			tail.slab = page.slab
			tail.prev = nil
			tail.next = nil
		end
	end

	if page.next == nil then
		pool.free.next.prev = page
		page.next = pool.free.next
		pool.free.next = page
		page.prev = pool.free
	end

	if n_page > 0 then
		local page1 = pool.pages + n_page - 1
		if page1.slab > 1 then
			page1 = page1 - page1.slab + 1
		end
		if page1.next ~= nil and ffi.cast("uintptr_t", page1.prev) % 4 == SLAB_PAGE then
			page1.next.prev = page1.prev
			page1.prev.next = page1.next
			--#--
			page1.slab = page1.slab + page.slab
			page1.next = page.next
			page.next.prev = page1
			page1.prev = page.prev
			page.prev.next = page1
			--#--
			page.slab = 0
			page.prev = nil
			page.next = nil
			--#--
			local tail = page1 + page1.slab - 1
			tail.slab = page1.slab
			tail.prev = nil
			tail.next = nil
		end
	end
end

local function slab_alloc(pool, size)
	if size > MAX_SIZE then
		local n_pages = ceil(size / PAGE_SIZE)
		local page = alloc_pages(pool, n_pages)
		if page then
			return pool.start + (page - pool.pages) * PAGE_SIZE
		end
	else
		local slot
		for i=0,C.SLAB_N_SLOTS-1 do
			slot = pool.slots + i
			if slot.slab >= size then
				break
			end
		end

		local typ
		if slot.slab < EXACT_SIZE then
			typ = SLAB_SMALL
		elseif slot.slab > EXACT_SIZE then
			typ = SLAB_BIG
		else
			typ = SLAB_EXACT
		end

		local ret
		local page = slot.next

		::find_slab::

		if page == slot then
			page = alloc_pages(pool, 1)
			if page == nil then return nil end
			slot.next.prev = page
			page.next = slot.next
			slot.next = page
			page.prev = ffi.cast("slab_page_t*", ffi.cast("uintptr_t", slot) + typ)
			if typ == SLAB_SMALL then
				page.slab = slot.slab
				local bitmap = pool.start + (page - pool.pages) * PAGE_SIZE
				local n_bytes = PAGE_SIZE / slot.slab / 8
				for i=0, n_bytes - 1 do
					bitmap[i] = 0
				end
				local meta_slabs = ceil(n_bytes / slot.slab)
				assert(floor(meta_slabs / 8) <= 1)
				bitmap[0] = lshift(1, meta_slabs) - 1
			else
				page.slab = 0
			end
		end

		if typ == SLAB_SMALL then
			local bitmap = pool.start + (page - pool.pages) * PAGE_SIZE
			local wptr = ffi.cast("uintptr_t*", bitmap)
			local n_bytes = PAGE_SIZE / slot.slab / 8
			for i=0, n_bytes/uintptr_sz - 1 do
				if wptr[i] ~= uintptr_max then
					local cptr = ffi.cast("unsigned char*", wptr + i)
					for j=0, uintptr_sz-1 do
						local c = cptr[j]
						if c ~= 0xff then
							for k=0, 7 do
								local b2 = lshift(1, k)
								if band(c, b2) == 0 then
									cptr[j] = ffi.cast("unsigned char", bor(c, b2))
									ret = bitmap + slot.slab * (i*uintptr_sz*8 + j*8 + k)
									break
								end
							end
							break
						end
					end
					assert(ret ~= nil)
					break
				end
			end
		else
			local n_bits = PAGE_SIZE / slot.slab
			local slab = page.slab
			for i=0, n_bits - 1 do
				local b = lshift(1, i)
				if band(slab, b) == 0 then
					page.slab = ffi.cast("uintptr_t", bor(slab, b))
					ret = pool.start + (page - pool.pages) * PAGE_SIZE + slot.slab * i
					break
				end
			end
		end

		if ret == nil then
			page.prev.next = page.next
			page.next.prev = page.prev
			local next_page = page.next
			page.next = nil
			page = next_page
			goto find_slab
		end

		return ret
	end
end

local function slab_free(pool, ptr)
	ptr = ffi.cast("unsigned char*", ptr)
	local n_page = floor((ptr - pool.start) / PAGE_SIZE)
	local page = pool.pages[n_page]
	local typ = ffi.cast("uintptr_t", page.prev) % 4
	if typ == SLAB_PAGE then
		return free_pages(pool, n_page)
	end

	local slot = ffi.cast("uintptr_t", page.prev) / 4 * 4
	slot = ffi.cast("slab_page_t*", slot)
	if page.next == nil then
		slot.next.prev = page
		page.next = slot.next
		slot.next = page
	end

	if typ == SLAB_SMALL then
		local bitmap = pool.start + n_page * PAGE_SIZE
		local delta = ptr - bitmap
		local n_bit = delta / slot.slab
		local n_unit = floor(n_bit / 8)
		n_bit = n_bit % 8
		local b1 = bitmap[n_unit]
		local b2 = lshift(1, n_bit)
		assert(band(b1, b2) ~= 0)
		bitmap[n_unit] = ffi.cast("unsigned char", band(b1, bnot(b2)))

		local is_free_page = true
		local wptr = ffi.cast("uintptr_t*", bitmap)
		for i=0, PAGE_SIZE / slot.slab / 8 / uintptr_sz - 1 do
			if wptr[i] ~= 0 then
				is_free_page = false
				break
			end
		end

		if is_free_page then
			page.prev.next = page.next
			page.next.prev = page.prev
			page.slab = 1
			return free_pages(pool, n_page)
		end
	else
		local delta = ptr - (pool.start + n_page * PAGE_SIZE)
		local n_bit = delta / slot.slab
		local b = lshift(1, n_bit)
		assert(band(page.slab, b) ~= 0)
		page.slab = band(page.slab, bnot(b))
		if page.slab == 0 then
			page.prev.next = page.next
			page.next.prev = page.prev
			page.slab = 1
			return free_pages(pool, n_page)
		end
	end
end

return {
	pool_init = slab_pool_init,
	alloc = slab_alloc,
	free = slab_free,
}
