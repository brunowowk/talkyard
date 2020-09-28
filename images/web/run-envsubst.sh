#!/bin/bash

# Replace variable placeholders, like in 'limit_rate_after ${ED_NGX_LIMIT_RATE_AFTER}',
# with OS environment variable values.
# Don't forget to add default values in the Dockerfile. [0KW2UY3]

vars='
  \${TY_NGX_ERR_LOG_LEVEL}
  \${ED_NGX_LIMIT_CONN_PER_IP}
  \${ED_NGX_LIMIT_CONN_PER_SERVER}
  \${ED_NGX_LIMIT_REQ_PER_IP}
  \${ED_NGX_LIMIT_REQ_PER_IP_BURST}
  \${ED_NGX_LIMIT_REQ_PER_SERVER}
  \${ED_NGX_LIMIT_REQ_PER_SERVER_BURST}
  \${TY_NGX_LIMIT_REQ_BODY_SIZE}
  \${ED_NGX_LIMIT_RATE}
  \${ED_NGX_LIMIT_RATE_AFTER}
  \${TY_MAX_AGE_YEAR}
  \${TY_MAX_AGE_MONTH}
  \${TY_MAX_AGE_WEEK}
  \${TY_MAX_AGE_DAY}'


# Or use instead: https://github.com/a8m/envsubst
# so can place default values in the placeholders instead, not
# everything here.
TY_NGX_ERR_LOG_LEVEL="${TY_NGX_ERR_LOG_LEVEL:-warn}" \
  envsubst "$vars" < /etc/nginx/nginx.conf.template           > /etc/nginx/nginx.conf

envsubst "$vars" < /etc/nginx/http-limits.conf.template       > /etc/nginx/http-limits.conf
envsubst "$vars" < /etc/nginx/server-limits.conf.template     > /etc/nginx/server-limits.conf
envsubst "$vars" < /etc/nginx/server-locations.conf.template  > /etc/nginx/server-locations.conf

# Old, can remove? See comments in Dockerfile.
envsubst "$vars" < /etc/nginx/vhost.conf.template  > /etc/nginx/vhost.conf
envsubst "$vars" < /etc/nginx/server.conf.template > /etc/nginx/server.conf


