local lux_cache = {}

local function parseHashLines(chunk,brackets,esc)
	local append,format,strsub,strfind = table.insert,string.format,string.sub,string.find
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
local function lux_compile(str,env)
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

local function lux_execute(fn, req, rsp)
	local out = {}
	local res,err = xpcall(function() fn(req, rsp,
	function(s)
		out[#out+1] = s
	end) end,debug.traceback)
	if not res then
		if env._debug then print(code) end
		return nil,err
	end
	return table.concat(out)
end

local function service(req, rsp, cf)
	if not lux_cache[req.url.path] then
		local path = (cf.root or ".") .. '/' .. req.url.path
		local f = io.open(path)
		assert(f)
		local str = f:read('*a')
		assert(str)
		lux_cache[req.url.path] = lux_compile(str, {_parent=_G})
	end

	local out = lux_execute(lux_cache[req.url.path], req, rsp)
	rsp.headers["content-length"] = #out
	rsp:say(out)
end

return {service = service}
