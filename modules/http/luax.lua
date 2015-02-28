local luax_cache = {}
local append,format,strsub,strfind = table.insert,string.format,string.sub,string.find

local function parseHashLines(chunk,brackets,esc)
	local exec_pat = "()$(%b"..brackets..")()"

	local function parseDollarParen(pieces, chunk, s, e)
		local s = 1
		for term, executed, e in chunk:gmatch (exec_pat) do
			executed = '('..strsub(executed,2,-2)..')'
			append(pieces,
			  format("%q..(%s or '')..",strsub(chunk,s, term - 1), executed))
			s = e
		end
		append(pieces, format("%q", strsub(chunk,s)))
	end

	local esc_pat = esc.."+([^\n]*\n?)"
	local esc_pat1, esc_pat2 = "^"..esc_pat, "\n"..esc_pat
	local  pieces, s = {"return function(req,rsp,_put) ", n = 1}, 1
	while true do
		local ss, e, lua = strfind (chunk,esc_pat1, s)
		if not e then
			ss, e, lua = strfind(chunk,esc_pat2, s)
			append(pieces, "_put(")
			parseDollarParen(pieces, strsub(chunk,s, ss))
			append(pieces, ")")
			if not e then break end
		end
		append(pieces, lua)
		s = e + 1
	end
	append(pieces, " end")
	return table.concat(pieces)
end

--- expand the template using the specified environment.
-- There are three special fields in the environment table `env`
--
--   * `_parent` continue looking up in this table (e.g. `_parent=_G`)
--   * `_brackets`; default is '()', can be any suitable bracket pair
--   * `_escape`; default is '#'
--
-- @string str the template string
-- @tab[opt] env the environment
local function luax_compile(str,env)
	env = env or {}
	if rawget(env,"_parent") then
		setmetatable(env,{__index = env._parent})
	end
	local brackets = rawget(env,"_brackets") or '{}'
	local escape = rawget(env,"_escape") or '#'
	local code = parseHashLines(str,brackets,escape)
	--print(code)
	local fn,err = loadstring(code)
	setfenv(fn, env)
	if not fn then return nil,err end
	return fn()
end

local function service(req, rsp)
	local path = req.url:path()
	if not luax_cache[path] then
		local fpath = {(req.lcf.root or "."), "", path}
		if req.lcf.luax_prefix then fpath[2] = req.lcf.luax_prefix end
		fpath = table.concat(fpath, "/")
		local f = io.open(fpath)
		assert(f)
		local str = f:read('*a')
		assert(str)
		luax_cache[path] = luax_compile(str, {_parent=_G})
	end

	local fn = luax_cache[path]
	local ret,err = pcall(fn, req, rsp, function(s) rsp:say(s) end)
	if ret == false then
		return nil,err
	end
end

return service
