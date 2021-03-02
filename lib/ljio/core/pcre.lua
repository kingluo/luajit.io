local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")
local bor = bit.bor
local lshift = bit.lshift
local pcre = ffi.load("pcre")
local strfmt = string.format
local tinsert = table.insert
local tconcat = table.concat

ffi.cdef[[
int atoi(const char *nptr);

typedef struct real_pcre pcre;
typedef struct pcre_extra pcre_extra;
typedef const char * PCRE_SPTR;

static const int PCRE_STUDY_JIT_COMPILE       = 1;
static const int PCRE_INFO_CAPTURECOUNT       = 2;
static const int PCRE_INFO_NAMEENTRYSIZE      = 7;
static const int PCRE_INFO_NAMECOUNT          = 8;
static const int PCRE_INFO_NAMETABLE          = 9;
static const int PCRE_ERROR_NOMATCH          = -1;

static const int32_t PCRE_CASELESS           = 0x00000001;  /* C1       */
static const int32_t PCRE_MULTILINE          = 0x00000002;  /* C1       */
static const int32_t PCRE_DOTALL             = 0x00000004;  /* C1       */
static const int32_t PCRE_EXTENDED           = 0x00000008;  /* C1       */
static const int32_t PCRE_ANCHORED           = 0x00000010;  /* C4 E D   */
static const int32_t PCRE_DUPNAMES           = 0x00080000;  /* C1       */
static const int32_t PCRE_JAVASCRIPT_COMPAT  = 0x02000000;  /* C5       */
static const int32_t PCRE_UTF8               = 0x00000800;  /* C4        )          */
static const int32_t PCRE_NO_UTF8_CHECK      = 0x00002000;  /* C1 E D J  )          */

pcre *pcre_compile(const char *, int, const char **, int *,
                   const unsigned char *);
pcre_extra *pcre_study(const pcre *, int, const char **);
int pcre_exec(const pcre *, const pcre_extra *, PCRE_SPTR,
              int, int, int, int *, int);
int pcre_dfa_exec(const pcre *code, const pcre_extra *extra,
    const char *subject, int length, int startoffset, int options,
    int *ovector, int ovecsize, int *workspace, int wscount);
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
local ws = ffi.new("int[?]", 100)

local all_options = {
    [("a"):byte()] = pcre.PCRE_ANCHORED,
    [("D"):byte()] = pcre.PCRE_DUPNAMES,
    [("i"):byte()] = pcre.PCRE_CASELESS,
    [("J"):byte()] = pcre.PCRE_JAVASCRIPT_COMPAT,
    [("m"):byte()] = pcre.PCRE_MULTILINE,
    [("s"):byte()] = pcre.PCRE_DOTALL,
    [("u"):byte()] = pcre.PCRE_UTF8,
    [("U"):byte()] = pcre.PCRE_UTF8,
    [("x"):byte()] = pcre.PCRE_EXTENDED,
}

local j_flag = ("j"):byte()
local o_flag = ("o"):byte()
local d_flag = ("d"):byte()

once_flag = false
jit_flag = false

local function match_ll(subject, subject_len, regex, options, ctx)
    -- parse options
    local flags = {}
    local opts = 0
    local exec_opts = 0
    if options then
        local coptions = ffi.cast("const char*", options)
        for i = 0, #options-1 do
            local c = coptions[i]
            flags[c] = true
            local opt = all_options[c]
            if opt then
                opts = bor(opts, opt)
                if opt == pcre.PCRE_UTF8 then
                    exec_opts = pcre.PCRE_NO_UTF8_CHECK
                end
            end
        end
    end

    if flags[d_flag] then
        -- pcre does not support JIT for DFA mode yet,
        -- so if DFA mode is specified, we turn off JIT automatically
        flags[j_flag] = nil
    end

    local cache_key = strfmt("%s:%08x", regex, opts)

    local r, re, ovector_cnt, ovector, name_idx, capture_count_val

    if flags[o_flag] then
        local c = re_caches[cache_key]
        if c then
            r = c.r
            ovector_cnt = c.ovector_cnt
            ovector = c.ovector
            capture_count_val = c.capture_count
            name_idx = c.name_idx
            re = c.re
        end
    end

    if not r then
        r = pcre.pcre_compile(regex, opts, err, erroffset, nil)
        if err[0] ~= nil then
            local e = ffi.string(err[0])
            return nil, e
        end

        pcre.pcre_fullinfo(r, nil, pcre.PCRE_INFO_CAPTURECOUNT, capture_count)
        pcre.pcre_fullinfo(r, nil, pcre.PCRE_INFO_NAMECOUNT, name_count)
        pcre.pcre_fullinfo(r, nil, pcre.PCRE_INFO_NAMEENTRYSIZE, name_entry_size)
        pcre.pcre_fullinfo(r, nil, pcre.PCRE_INFO_NAMETABLE, name_table)

        name_idx = {}
        for i = 0, name_count[0] - 1 do
            local name_entry = name_table[0] + i * name_entry_size[0]
            local name = ffi.string(name_entry + 2)
            local idx = bor(lshift(name_entry[0], 8), name_entry[1])
            tinsert(name_idx, {name, idx})
        end

        capture_count_val = capture_count[0]
        ovector_cnt = (capture_count[0] + 1) * 3
        ovector = ffi.new("int[?]", ovector_cnt)

        if once_flag then
            re_caches[cache_key] = {
                r = r,
                name_idx = name_idx,
                ovector_cnt = ovector_cnt,
                ovector = ovector,
                capture_count = capture_count_val,
            }
        end
    end

    if not re and flags[jit_flag] then
        re = pcre.pcre_study(r, pcre.PCRE_STUDY_JIT_COMPILE, err)
        if err[0] ~= nil then
            if not once_flag then
                pcre.pcre_free(r)
            end
            local e = ffi.string(err[0])
            return nil, e
        end

        if once_flag then
            re_caches[cache_key].re = re
        end
    end

    local pos = 0
    if ctx and ctx.pos then
        if ctx.pos <= 0 then
            pos = 0
        else
            pos = ctx.pos - 1
        end
    end

    local rc

    if flags[d_flag] then
        ovector_cnt = 2
        capture_count_val = 0
        rc = pcre.pcre_dfa_exec(r, re, subject, subject_len, pos, exec_opts, ovector, ovector_cnt, ws, 100)
        if rc == 0 then
            rc = 1
        end
    else
        rc = pcre.pcre_exec(r, re, subject, subject_len, pos, exec_opts, ovector, ovector_cnt)
    end

    if rc > 0 and ctx then
        ctx.pos = ovector[1] + 1
    end

    if not once_flag then
        if re then
            pcre.pcre_free_study(re)
        end
        pcre.pcre_free(r)
    end

    return rc, nil, ovector, name_idx, capture_count_val
end

local function match(subject, regex, options, ctx, res_table)
    res_table = res_table or {}

    local strptr = ffi.cast("const char*", subject)
    local subject_len = #subject

    local rc, err, ovector, name_idx, capture_count = match_ll(strptr, subject_len, regex, options, ctx, res_table)

    if err then
        return nil, err
    end

    if rc <= 0 then
        if rc == pcre.PCRE_ERROR_NOMATCH then
            return nil
        else
            return nil, rc
        end
    end

    for i = 0, rc-1 do
        local cap
        if ovector[i*2] ~= -1 then
            cap = ffi.string(strptr + ovector[i*2], ovector[i*2+1] - ovector[i*2])
        else
            cap = false
        end
        res_table[i] = cap
    end

    for i = rc, capture_count do
        res_table[i] = false
    end

    local do_dup = false
    if options then
        do_dup = options:find("D", 0, true)
    end
    for _, v in ipairs(name_idx) do
        local name = v[1]
        local idx = v[2]
        local val = res_table[idx]
        if val ~= nil then
            if do_dup then
                if res_table[name] == nil then
                    res_table[name] = {}
                end
                tinsert(res_table[name], val)
            else
                res_table[name] = val
            end
        end
    end

    return res_table
end

local function find(subject, regex, options, ctx, nth)
    local strptr = ffi.cast("const char*", subject)
    local subject_len = #subject

    local rc, err, ovector, name_idx, capture_count = match_ll(strptr, subject_len, regex, options, ctx)

    if err then
        return nil, err
    end

    if rc <= 0 then
        if rc == pcre.PCRE_ERROR_NOMATCH then
            return nil
        else
            return nil, rc
        end
    end

    nth = nth or 0
    if nth > 0 then
        if capture_count < nth then
            return nil, "argument nth out of index"
        end
    end

    return ovector[nth*2] + 1, ovector[nth*2+1], nil
end

local DOLLAR = ("$"):byte()
local BRACKET1 = ("{"):byte()
local BRACKET2 = ("}"):byte()
local DIGIT1 = ("0"):byte()
local DIGIT2 = ("9"):byte()

local function sub_ll(subject, regex, replace, options, limit, strptr, prev)
    strptr = strptr or ffi.cast("const char*", subject)
    prev = prev or {cnt = 0, len = #subject}

    local rc, err, ovector, name_idx, capture_count = match_ll(strptr, prev.len, regex, options)

    if err then
        return nil, err
    end

    if rc <= 0 then
        if rc == pcre.PCRE_ERROR_NOMATCH then
            tinsert(prev, ffi.string(strptr))
            return tconcat(prev, ""), prev.cnt
        else
            return nil, rc
        end
    end

    -- collect all captures
    local res_table = {}
    for i = 0, rc-1 do
        local cap
        if ovector[i*2] ~= -1 then
            cap = ffi.string(strptr + ovector[i*2], ovector[i*2+1] - ovector[i*2])
        else
            cap = ""
        end
        res_table[i] = cap
    end

    for i = rc, capture_count do
        res_table[i] = ""
    end

    -- compile the replacement template
    local replace_compiled = replace
    if type(replace) == "function" then
        replace_compiled = replace(res_table)
    else
        local strs = {}
        local ptr = ffi.cast("const char*", replace)
        local pos1 = 0
        local pos2 = -1
        local i = 0

        while i < #replace do
            if ptr[i] == DOLLAR then
                pos2 = i
                if i + 1 >= #replace then
                    return nil, "failed to compile the replacement template"
                end
                local c1 = ptr[i+1]
                if c1 == BRACKET1 and i + 3 >= #replace then
                    return nil, "failed to compile the replacement template"
                end
                if c1 == BRACKET1 or (c1 >= DIGIT1 and c1 <= DIGIT2) then
                    i = i + ((c1 == BRACKET1) and 2 or 1)
                    local c2
                    while i < #replace do
                        c2 = ptr[i]
                        if c2 < DIGIT1 or c2 > DIGIT2 then
                            break
                        end
                        i = i + 1
                    end
                    if c2 == BRACKET2 then
                        i = i + 1
                    end
                    if c1 == BRACKET1 and c2 ~= BRACKET2 then
                        return nil, "failed to compile the replacement template"
                    end
                    local idx = C.atoi(ptr + pos2 + 1)
                    tinsert(strs, ffi.string(ptr + pos1, pos2 - pos1))
                    tinsert(strs, res_table[idx])
                    pos1 = i
                    pos2 = -1
                elseif c1 == DOLLAR then
                    tinsert(strs, ffi.string(ptr + pos1, pos2 - pos1 + 1))
                    pos1 = i + 2
                    pos2 = -1
                    i = i + 2
                else
                    return nil, "failed to compile the replacement template"
                end
            else
                i = i + 1
            end
        end
        if #strs > 0 then
            if pos1 < i then
                tinsert(strs, ffi.string(ptr + pos1, i - pos1))
            end
            replace_compiled = tconcat(strs)
        end
    end

    -- do replacement
    tinsert(prev, ffi.string(strptr, ovector[0]))
    tinsert(prev, replace_compiled)
    strptr = strptr + ovector[1]
    prev.cnt = prev.cnt + 1
    prev.len = prev.len - ovector[1]
    if prev.len == 0 then
        return tconcat(prev, ""), prev.cnt
    elseif prev.cnt == limit then
        tinsert(prev, ffi.string(strptr))
        return tconcat(prev, ""), prev.cnt
    end

    return sub_ll(subject, regex, replace, options, once, strptr, prev)
end

local function sub(subject, regex, replace, options)
    return sub_ll(subject, regex, replace, options, 1)
end

local function gsub(subject, regex, replace, options)
    return sub_ll(subject, regex, replace, options, -1)
end

return {
    match = match,
    find = find,
    sub = sub,
    gsub = gsub,
}
