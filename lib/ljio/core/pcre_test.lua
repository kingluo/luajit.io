local re = loadfile("pcre.lua")()
local match = re.match
local find = re.find
local sub = re.sub
local gsub = re.gsub

local m, err = match("hello, 1234", "[0-9]+")
assert(m[0] == "1234")

local m, err = match("This is <something> <something else> <something further> no more", "<.*>", "d")
assert(m[0] == "<something> <something else> <something further>")

local m, err = match("hello, 1234", "([0-9])[0-9]+")
assert(m[0] == "1234")
assert(m[1] == "1")

local m, err = match("hello, 1234", "([0-9])(?<remaining>[0-9]+)")
assert(m[0] == "1234")
assert(m[1] == "1")
assert(m[2] == "234")
assert(m["remaining"] == "234")

local m, err = match("hello, world", "(world)|(?<xxx>hello)|(?<named>howdy)")
assert(m[0] == "hello")
assert(m[1] == false)
assert(m[2] == "hello")
assert(m[3] == false)
assert(m["named"] == false)

local m = match("hello, world", "(?<named>\\w+), (?<named>\\w+)", "D")
assert(m["named"][1] == "hello")
assert(m["named"][2] == "world")

local m, err = match("hello, world", "HEL LO", "ix")
assert(m[0] == "hello")

local m, err = match("hello, 美好生活", "HELLO, (.{2})", "iu")
assert(m[0] == "hello, 美好")
assert(m[1] == "美好")

local ctx = {}
local m, err = match("1234, hello", "[0-9]+", "", ctx)
assert(m[0] == "1234")
assert(ctx.pos == 5)

local ctx = { pos = 2 }
local m, err = match("1234, hello", "[0-9]+", "", ctx)
assert(m[0] == "234")
assert(ctx.pos == 5)

--#--
local s = "hello, 1234"
local from, to, err = find(s, "([0-9]+)", "jo")
assert(from == 8)
assert(to == 11)
assert(string.sub(s, from, to) == "1234")

local str = "hello, 1234"
local from, to = find(str, "([0-9])([0-9]+)", "jo", nil, 2)
assert(string.sub(str, from, to) == "234")

--#--
local newstr, n, err = sub("hello, 1234", "([0-9])[0-9]", "[$0][$1]")
assert(newstr == "hello, [12][1]34")
assert(n == 1)

local newstr, n, err = sub("hello, 1234", "[0-9]", "${0}00")
assert(newstr == "hello, 100234")
assert(n == 1)

local newstr, n, err = sub("hello, 1234", "[0-9]", "$$")
assert(newstr == "hello, $234")
assert(n == 1)

local func = function (m)
    return "[" .. m[0] .. "][" .. m[1] .. "]"
end
local newstr, n, err = sub("hello, 1234", "( [0-9] ) [0-9]", func, "x")
assert(newstr == "hello, [12][1]34")
assert(n == 1)

--#--
local newstr, n, err = gsub("hello, world", "([a-z])[a-z]+", "[$0,$1]", "i")
assert(newstr == "[hello,h], [world,w]")
assert(n == 2)

local func = function (m)
    return "[" .. m[0] .. "," .. m[1] .. "]"
end
local newstr, n, err = gsub("hello, world", "([a-z])[a-z]+", func, "i")
assert(newstr == "[hello,h], [world,w]")
assert(n == 2)
