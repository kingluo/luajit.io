local ffi = require("ffi")
local pcre = ffi.load("pcre")

ffi.cdef[[
typedef struct real_pcre pcre;
typedef struct pcre_extra pcre_extra;
typedef const char * PCRE_SPTR;

static const int PCRE_STUDY_JIT_COMPILE       = 1;
static const int PCRE_INFO_CAPTURECOUNT       = 2;
static const int PCRE_INFO_NAMEENTRYSIZE      = 7;
static const int PCRE_INFO_NAMECOUNT          = 8;
static const int PCRE_INFO_NAMETABLE          = 9;
static const int PCRE_ERROR_NOMATCH          = -1;

pcre *pcre_compile(const char *, int, const char **, int *,
                   const unsigned char *);
pcre_extra *pcre_study(const pcre *, int, const char **);
int pcre_exec(const pcre *, const pcre_extra *, PCRE_SPTR,
              int, int, int, int *, int);
void pcre_free_study(pcre_extra *);
void (*pcre_free)(void *);
int pcre_fullinfo(const pcre *code, const pcre_extra *extra, int what, void *where);
int pcre_get_stringnumber(const pcre *code, const char *name);
]]

local re_caches = {}

local err = ffi.new("const char *[1]")
local erroffset = ffi.new("int[1]")

local capture_count = ffi.new("int[1]")
local name_count = ffi.new("int[1]")
local name_entry_size = ffi.new("int[1]")
local name_table = ffi.new("const char *[1]")

local function match_ll(subject, subject_len, regex, options, ctx)
	local once_flag = regex:find("o", 0, true)
	local jit_flag = regex:find("o", 0, true)
	local r, re, ovector_cnt, ovector, name_idx

	if once_flag then
		local c = re_caches[regex]
		if c then
			r = c.r
			ovector_cnt = c.ovector_cnt
			ovector = c.ovector
			name_idx = c.name_idx
			re = c.re
		end
	end

	if not r then
		r = pcre.pcre_compile(regex, 0, err, erroffset, nil)
		if err[0] ~= nil then
			local e = ffi.string(err[0])
			print("err", e)
			print("erroffset", erroffset[0])
			return nil, e
		end

		pcre.pcre_fullinfo(r, nil, pcre.PCRE_INFO_CAPTURECOUNT, capture_count)
		pcre.pcre_fullinfo(r, nil, pcre.PCRE_INFO_NAMECOUNT, name_count)
		pcre.pcre_fullinfo(r, nil, pcre.PCRE_INFO_NAMEENTRYSIZE, name_entry_size)
		pcre.pcre_fullinfo(r, nil, pcre.PCRE_INFO_NAMETABLE, name_table)

		name_idx = {}
		for i = 0, name_count[0] - 1 do
			local n = ffi.string(name_table[i] + 2, name_entry_size[i])
			name_idx[n] = pcre.pcre_get_stringnumber(r, n)
		end

		ovector_cnt = (capture_count[0] + 1) * 3
		ovector = ffi.new("int[?]", ovector_cnt)
		if once_flag then
			re_caches[regex] = {
				r = r,
				name_idx = name_idx,
				ovector_cnt = ovector_cnt,
				ovector = ovector,
			}
		end
	end

	if not re and jit_flag then
		re = pcre.pcre_study(r, pcre.PCRE_STUDY_JIT_COMPILE, err)
		if err[0] ~= nil then
			if not once_flag then
				pcre.pcre_free(r)
			end
			local e = ffi.string(err[0])
			print("err", e)
			return nil, e
		end

		if once_flag then
			re_caches[regex].re = re
		end
	end

	if ctx and ctx.pos > 0 then
		subject = subject + ctx.pos
		subject_len = subject_len - ctx.pos
	end
	local rc = pcre.pcre_exec(r, re, subject, subject_len, 0, 0, ovector, ovector_cnt)

	if not once_flag then
		if re then
			pcre.pcre_free_study(re)
		end
		pcre.pcre_free(r)
	end

	return rc, nil, ovector, name_idx
end

local function match(subject, regex, options, ctx, res_table)
	res_table = res_table or {}

	local strptr = ffi.cast("const char*", subject)
	local subject_len = #subject

	local rc, err, ovector, name_idx = match_ll(strptr, subject_len, regex, options, ctx, res_table)
	if err then
		return nil, err
	end

	for i = 0, rc - 1 do
		local cap = ffi.string(strptr + ovector[i*2], ovector[i*2+1] - ovector[i*2])
		res_table[i] = cap
	end

	for k, v in pairs(name_idx) do
		res_table[k] = res_table[v]
	end

	return res_table
end

local function find(subject, regex, options, ctx, nth)
	local strptr = ffi.cast("const char*", subject)
	local subject_len = #subject
	local rc, err, ovector, name_idx = match_ll(strptr, subject_len, regex, options, ctx)
	if err then
		return nil, nil, err
	end

	nth = nth or 0
	if nth > 0 then
		print(rc, nth)
		if rc <= nth then
			return nil, nil, "argument nth out of index"
		end
	end
	return ovector[nth*2] + 1, ovector[nth*2+1], nil
end

local function sub_ll(subject, regex, replace, options, limit, strptr, prev)
	strptr = strptr or ffi.cast("const char*", subject)
	prev = prev or {cnt = 0, len = #subject}

	local rc, err, ovector, name_idx = match_ll(strptr, prev.len, regex, options)

	if err then
		return nil, 0, err
	end

	if rc <= 0 then
		if rc == pcre.PCRE_ERROR_NOMATCH then
			table.insert(prev, ffi.string(strptr))
			return table.concat(prev, ""), prev.cnt, nil
		else
			return nil, 0, rc
		end
	end

	local res_table = {}
	for i = 0, rc - 1 do
		local cap = ffi.string(strptr + ovector[i*2], ovector[i*2+1] - ovector[i*2])
		res_table[i] = cap
	end

	if replace:find("$", 0, true) then
		replace = replace:gsub("%${?(%d+)}?", function(idx) return res_table[tonumber(idx)] end)
		replace = replace:gsub("%$%$", "$")
	end

	local newstr = ffi.string(strptr, ovector[0]) .. replace
	-- print("debug", ffi.string(strptr), replace, ovector[0], ovector[1])
	table.insert(prev, newstr)
	strptr = strptr + ovector[1]
	prev.cnt = prev.cnt + 1
	prev.len = prev.len - ovector[1]
	if prev.len == 0 then
		return table.concat(prev, ""), prev.cnt, nil
	elseif prev.cnt == limit then
		table.insert(prev, ffi.string(strptr))
		return table.concat(prev, ""), prev.cnt, nil
	end

	return sub_ll(subject, regex, replace, options, once, strptr, prev)
end

local function sub(subject, regex, replace, options)
	return sub_ll(subject, regex, replace, options, 1)
end

local function gsub(subject, regex, replace, options)
	return sub_ll(subject, regex, replace, options, -1)
end

local subject = "abcd--gd###abcd"
local pattern = "ab(cd)"
local res = match(subject, pattern, "jo")
for k, v in pairs(res) do
	print(k, v)
end
local pos1, pos2, err = find(subject, pattern, "jo", nil, 2)
if err then
	print(err)
else
	print(subject:sub(pos1, pos2))
end

local str, n, err = sub(subject, pattern, "${1}*$1", "jo")
if err then
	print("err",err)
else
	print(str, n)
end

local str, n, err = sub("foo bar fe ", "\\s", "%20", "jo")
if err then
	print("err",err)
else
	print(str, n)
end

local str, n, err = gsub("foo bar fe ", "\\s", "%20", "jo")
if err then
	print("err",err)
else
	print(str, n)
end

return {
	match = match,
	find = find,
	sub = sub,
	gsub = gsub,
}
