-- Copyright (C) Jinhua Luo

local type = type
local tostring = tostring
local tinsert = table.insert
local tremove = table.remove
local tconcat = table.concat
local ipairs = ipairs

local function copy_table(dst, t)
    for i = 1, #t do
        local v = t[i]
        local typ = type(v)
        if typ == "table" then
            copy_table(dst, v)
        else
            if typ == "boolean" then
                v = v and "true" or "false"
            elseif typ == "nil" then
                v = "nil"
            elseif typ ~= "string" then
                v = tostring(v)
            end
            tinsert(dst, v)
        end
    end
end

local function copy_values_ll(dst, v)
    local typ = type(v)
    if typ == "table" then
        copy_table(dst, v)
    else
        if typ == "boolean" then
            v = v and "true" or "false"
        elseif typ == "nil" then
            v = "nil"
        elseif typ ~= "string" then
            v = tostring(v)
        end
        tinsert(dst, v)
    end
end

local function copy_value(tbl, ...)
    local n = select("#", ...)
    if n > 0 then
        local v = ...
        copy_values_ll(tbl, v)
        if n > 1 then
            return copy_value(tbl, select(2, ...))
        end
    end
end

local function copy_values(eol, ...)
    local tbl = {}

    local n = select("#", ...)
    if not eol and n == 1 then
        local v = ...
        local typ = type(v)
        if typ ~= "table" then
            if typ == "boolean" then
                v = v and "true" or "false"
            elseif typ == "nil" then
                v = "nil"
            elseif typ ~= "string" then
                v = tostring(v)
            end
            return v
        end
    end

    copy_value(tbl, ...)
    if eol then
        tinsert(tbl, eol)
    end

    return (tconcat(tbl))
end

return {
    copy_values = copy_values,
}
