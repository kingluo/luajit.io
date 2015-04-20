local ffi = require"ffi"
local null = ffi.new("void*")
local redis = require "resty.redis"

local function test_redis(req, rsp)
    local red = redis:new()

    -- red:set_timeout(1000) -- 1 sec

    -- or connect to a unix domain socket file listened
    -- by a redis server:
    --     local ok, err = red:connect("unix:/path/to/redis.sock")

    local ok, err = red:connect("127.0.0.1", 6379)
    if not ok then
        rsp:say("failed to connect: ", err)
        return
    end

    ok, err = red:set("dog", "an animal")
    if not ok then
        rsp:say("failed to set dog: ", err)
        return
    end

    rsp:say("set result: ", ok)

    local res, err = red:get("dog")
    if not res then
        rsp:say("failed to get dog: ", err)
        return
    end

    if res == null then
        rsp:say("dog not found.")
        return
    end

    rsp:say("dog: ", res)

    red:init_pipeline()
    red:set("cat", "Marry")
    red:set("horse", "Bob")
    red:get("cat")
    red:get("horse")
    local results, err = red:commit_pipeline()
    if not results then
        rsp:say("failed to commit the pipelined requests: ", err)
        return
    end

    for i, res in ipairs(results) do
        if type(res) == "table" then
            if not res[1] then
                rsp:say("failed to run command ", i, ": ", res[2])
            else
                -- process the table value
            end
        else
            -- process the scalar value
        end
    end

    -- put it into the connection pool of size 100,
    -- with 10 seconds max idle time
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        rsp:say("failed to set keepalive: ", err)
        return
    end

    -- or just close the connection right away:
    -- local ok, err = red:close()
    -- if not ok then
    --     rsp:say("failed to close: ", err)
    --     return
    -- end
end

return test_redis
