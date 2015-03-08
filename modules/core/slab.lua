local ffi = require("ffi")
local C = require("cdef")

local bit = require("bit")
local band = bit.band
local bor = bit.bor
local bnot = bit.bnot
local lshift = bit.lshift
local rshift = bit.rshift

local ceil = math.ceil
local tonumber = tonumber

ffi.cdef[[
static const int minshift = 3;
static const int maxshift = 11;
static const int n_slots = maxshift - minshift + 1;

typedef struct slab_page_s slab_page_t;
struct slab_page_s {
	uintptr_t slab;
	slab_page_t* next;
	uintptr_t prev;
};

typedef struct slab_pool_s slab_pool_t;
struct slab_pool_s {
	slab_page_t* pages;
	slab_page_t free;
	unsigned char* addr;
	unsigned char* start;
	unsigned char* end;
	slab_page_t slots[n_slots];
};
]]

local SLAB_PAGE = 0
local SLAB_SMALL = 1
local SLAB_EXACT = 2
local SLAB_BIG = 3
local SLAB_TYPE_MASK = 3
local SLAB_PTR_MASK = bnot(SLAB_TYPE_MASK)

local MIN_SIZE = lshift(1, C.minshift)
local MAX_SIZE = lshift(1, C.maxshift)
local EXACT_SIZE = lshift(1, 7)
local PAGESIZE = 4096
local align = bnot(PAGESIZE - 1)
local plsz = ffi.sizeof("slab_pool_t")

local function slab_pool_init(pool, size)
	local addr = ffi.cast("unsigned char*", pool)
	ffi.fill(addr, size)
	pool = ffi.cast("slab_pool_t*", pool)
	pool.addr = addr
	local s = band(tonumber(ffi.cast("uintptr_t", addr + plsz + PAGESIZE - 1)), align)
	s = tonumber(ffi.cast("uintptr_t", s))
	local e = band(tonumber(ffi.cast("uintptr_t", addr + size), align))
	e = tonumber(ffi.cast("uintptr_t", s))
	pool.start = ffi.cast("unsigned char*", s)
	pool.end = ffi.cast("unsigned char*", e)

	pool.pages = ffi.cast("slab_page_t*", addr + plsz)
	local n_pages = (pool.end - pool.start) / PAGESIZE
	local page = pool.pages[0]
	local tail = pool.pages[n_pages-1]

	page.slab = n_pages
	page.next = pool.free
	page.prev = pool.free

	pool.free.slab = n_pages
	pool.free.next = page
	pool.free.prev = page

	tail.slab = n_pages

	for i=0, C.n_slots-1 do
		local slot = pool.slots[i]
		slot.slab = lshift(1, C.minshift + i)
		slot.prev = slot
		slot.next = slot
	end

	return pool
end

local function alloc_pages(pool, n)
	local page = pool.free.next
	while page ~= pool.free do
		if page.slab >= n then
			local left = page.slab - n
			if left > 0 then
				page.slab = n
				local page2 = page + n
				page2.slab = left
				page2.prev = page.prev
				page.prev.next = page2
				page2.next = page.next
				page.next.prev = page2
			end
			page.prev = nil
			page.next = nil
			if page.slab > 1 then
				local tail = page + page.slab - 1
				tail.slab = page.slab
				tail.prev = nil
				tail.next = nil
			end
			return page
		end
		page = page.next
	end
end

local function free_pages(pool, page)
	local n = page - pool.pages
	if n + page.slab < pool.free.slab then
		local page2 = page + page.slab
		if page2.next ~= nil and band(tonumber(page2.prev), SLAB_TYPE_MASK) == SLAB_PAGE then
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
			page2 = page + page.slab - 1
			page2.slab = page.slab
			page2.prev = page
			page2.next = nil
		end
	end

	if page.next == nil then
		pool.free.next.prev = page
		page.next = pool.free.next
		pool.free.next = page
		page.prev = pool.free
	end

	if n > 0 then
		local page1 = pool.pages[n-1]
		if page1.slab > 1 then
			page1 = page1 - page1.slab + 1
		end
		if page1.next ~= nil and band(tonumber(page1.prev), SLAB_TYPE_MASK) == SLAB_PAGE then
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
		local n_pages = ceil(size / PAGESIZE)
		local page = alloc_pages(pool, n_pages)
		if page then
			return page.start + (page - pool.pages) * PAGESIZE
		end
	else
		local slot
		local slots = pool.slots
		for i=0,C.n_slots-1 do
			slot = slots + i
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

		if page == slot.prev then
			page = alloc_pages(pool, 1)
			if page == nil then return nil end
			slot.next.prev = page
			page.next = slot.next
			slot.next = page
			page.prev = ffi.cast("uintptr_t", bor(tonumber(ffi.cast("uintptr_t", slot)), typ))
			if typ == SLAB_SMALL then
				page.slab = slot.slab
				local bitmap = pool.start + (page - pool.pages) * PAGESIZE
				local n_bytes = PAGESIZE / slot.slab / 8
				for i=0, n_bytes - 1 do
					bitmap[i] = 0
				end
			elseif typ == SLAB_BIG then
				page.slab = ffi.cast("uintptr_t", lshift(tonumber(slot.slab), 16))
			else
				page.slab = 0
			end
		end

		if typ == SLAB_SMALL then
			local bitmap = pool.start + (page - pool.pages) * PAGESIZE
			local n_bytes = PAGESIZE / slot.slab / 8
			for i=0, n_bytes - 1 do
				local b1 = bitmap[i]
				if b1 ~= 0xff then
					for j=0, 7 do
						local b2 = lshift(1, j)
						if band(b1, b2) == 0 then
							bitmap[i] = bor(b1, b2)
							ret = bitmap + slot.slab * (i*8 + j + ceil(n_bytes / slot.slab))
							break
						end
					end
					assert(ret ~= nil)
					break
				end
			end
		else
			local n_bits = PAGESIZE / slot.slab
			local slab = tonumber(page.slab)
			for i=0, n_bits - 1 do
				local b = lshift(1, i)
				if band(slab, b) == 0 then
					page.slab = ffi.cast("uintptr_t", bor(slab, b))
					ret = pool.start + (page - pool.pages) * PAGESIZE + slot.slab * i
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
	local n_page = math.floor((ptr - pool.start) / PAGESIZE)
	local page = pool.pages[n_page]
	local typ = band(tonumber(page.prev), SLAB_TYPE_MASK)
	if typ == SLAB_PAGE then
		return free_pages(pool, page)
	elseif typ == SLAB_SMALL then
		local bitmap = pool.start + (page - pool.pages) * PAGESIZE
		local slot = ffi.cast("uintptr_t", band(tonumber(page.prev), SLAB_PTR_MASK))
		slot = ffi.cast("slab_page_t*", slot)
		local delta = ptr - bitmap
		local n_bit = delta / slot.slab
		local n_unit = math.floor(n_bit / 8)
		n_bit = n_bit % 8
		local b1 = bitmap[n_unit]
		local b2 = lshift(1, n_bit)
		if band(b1, b2) ~= 0 then
			bitmap[n_unit] = ffi.cast("unsigned char", bor(b1,b2))
		end

		local is_free_page = true
		for i=0, PAGESIZE / slot.slab / 8 do
			if bitmap[i] ~= 0xff then
				is_free_page = false
				break
			end
		end
		if is_free_page then
			free_pages(pool, page)
		end
	end
end
