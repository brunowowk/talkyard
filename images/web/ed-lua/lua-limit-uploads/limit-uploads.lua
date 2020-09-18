
local forbiddenMessage = false

forbiddenMessage = "TESTY_FORBDN"

-- if res.status == ngx.HTTP_OK then
--     return
-- end

if forbiddenMessage then
    ngx.status = 413
    ngx.header.content_type = 'text/plain'
    ngx.say("413 Request Entity Too Large [TyEUPLSZNGX]\n\nBandwidth exceeded. " .. forbiddenMessage)
    return ngx.exit(ngx.HTTP_OK)
end

