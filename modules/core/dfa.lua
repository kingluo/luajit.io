local ffi = require("ffi")
local C = require("cdef")

local dfa_pool = {}

local function dfa_compile(str)
	if dfa_pool[str] then
		return dfa_pool[str]
	end

	local dfa = {nodes={}}
	local node = {0,0,0}
	for i = 1,#str do
		local s = str:sub(1,i)
		node[1] = s
		node[2] = s:sub(#s)
		node[3] = #s
		if i == #str then
			table.insert(dfa.nodes, node)
			break
		end

		-- forward link
		local next_c = str:sub(i+1,i+1)
		local next_node = {0,0,0}
		node[next_c] = next_node

		-- backward links
		local ptr = ffi.cast("const char*", s)
		local n_node = #dfa.nodes
		for j=n_node,1,-1 do
			local n = dfa.nodes[j]
			local c = n[2]
			if not node[c] then
				local len = #n[1]-1
				if C.memcmp(n[1], ptr + #s - len, len) == 0 then
					node[c] = n
				end
			end
		end

		-- self link
		if node[2] ~= next_c and C.memcmp(ptr, ptr + 1, #s - 1) == 0 then
			node[node[2]] = node
		end

		table.insert(dfa.nodes, node)
		node = next_node
	end

	dfa.start = {"","",0,[dfa.nodes[1][2]] = dfa.nodes[1]}
	dfa.last = dfa.nodes[#dfa.nodes]

	dfa_pool[str] = dfa
	return dfa
end

-- local str = "nano"
-- local dfa = dfa_compile(str)
-- for _,node in ipairs(dfa.nodes) do
	-- print(node, node[1])
	-- for k,v in pairs(node) do
		-- if type(k) ~= "number" then
			-- print("> ",k,v)
		-- end
	-- end
-- end

return {
	compile = dfa_compile
}
