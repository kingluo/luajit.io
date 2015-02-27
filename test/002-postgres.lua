local pg = require("resty.postgres")

local function getdb()
	local db = pg:new()
	db:set_timeout(3000)
	local ok, err = db:connect({path="/var/run/postgresql/.s.PGSQL.5432",database="test",
		user="test",password="test",compact=false})
	return db,err
end

local function test_db(req, rsp)
	local db,err = getdb()
	if err then error(err) end
	local sqlstr = [[
		select * from send_sms_tbl order by id;
	]]
	local res,err,err_msg,tstatus = db:query(sqlstr)
	if not res then
		error(err)
	else
		for i,v in ipairs(res) do
			rsp:say(v.id, ",", v.sendtime, ",", v.status)
		end
	end
	db:set_keepalive()
end

return test_db
