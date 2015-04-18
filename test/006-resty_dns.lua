local function test(req, rsp)
    local resolver = require "resty.dns.resolver"
    local r, err = resolver:new{
        nameservers = {"8.8.8.8", {"8.8.4.4", 53} },
        retrans = 5,  -- 5 retransmissions on receive timeout
        timeout = 2000,  -- 2 sec
    }

    if not r then
        rsp:say("failed to instantiate the resolver: ", err)
        return
    end

    local answers, err = r:query("luajit.io")
    if not answers then
        rsp:say("failed to query the DNS server: ", err)
        return
    end

    if answers.errcode then
        rsp:say("server returned error code: ", answers.errcode,
                ": ", answers.errstr)
    end

    for i, ans in ipairs(answers) do
        rsp:say(ans.name, " ", ans.address or ans.cname,
                " type:", ans.type, " class:", ans.class,
                " ttl:", ans.ttl)
    end
end

return test
