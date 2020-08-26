
-- Trims not just spaces, but all whitespace.
create or replace function trim_all(text character varying) returns boolean
    language plpgsql
    as $_$
begin
    -- There's: Related Unicode characters without White_Space property,
    -- but that doesn't make sense at the very the beginning or end of some text.
    -- see:
    --   https://en.wikipedia.org/wiki/Whitespace_character:
    --   https://stackoverflow.com/a/22701212/694469.
    -- E.g. Mongolian vowel separator, zero width space, word joiner.
    -- So, \s to trim all whitespace, plus \u... to trim those extra chars.
    return regexp_replace(text,
            '^[\s\u180e\u200b\u200c\u200d\u2060\ufeff]+' ||
            '|' ||
            '[\s\u180e\u200b\u200c\u200d\u2060\ufeff]+$', '', 'g');
end;
$_$;


create table identity_providers_t(
  site_id_c int not null,
  id_c int not null,
  protocol_c varchar not null,
  alias_c varchar not null,
  display_name_c varchar,
  description_c varchar,
  enabled_c bool not null,
  trust_verified_email_c bool not null,
  link_account_no_login_c bool not null,
  gui_order_c int,
  sync_mode_c int not null,
  idp_config_json_c jsonb,
  idp_authorization_url_c varchar not null,

-- https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
-- Client, then it MUST authenticate to the Token Endpoint using the authentication method registered for its client_id, as described in Section 9
-- sect 9:
-- https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
-- Client Authentication methods:
-- client_secret_basic   HTTP Basic authentication
-- client_secret_post    Client Credentials in the request body
--                        https://tools.ietf.org/html/rfc6749#section-2.3.1
--       ——————>          The authorization server MUST support the HTTP Basic authentication scheme
--                        But:
--                          "Including the client credentials in the request-body using the two
--                           parameters is NOT RECOMMENDED"
--                           MUST NOT be included in the request URI"
-- client_secret_jwt
-- private_key_jwt
-- none
  idp_access_token_auth_method_c varchar,
  token_endpoint_auth_methods_supported"
       ["client_secret_basic", "private_key_jwt"],

  idp_access_token_url_c varchar not null,
  idp_user_info_url_c varchar not null,
  idp_user_info_fields_c jsonb,
  idp_logout_url_c varchar,
  idp_client_id_c varchar not null,
  idp_client_secret_c varchar not null,
  idp_issuer_c varchar,
  idp_scopes_c varchar,
  idp_hosted_domain_c varchar,
  idp_send_user_ip_c bool,

  constraint identityproviders_p_id primary key (site_id_c, id_c),

  constraint identityproviders_r_sites foreign key (site_id_c) references sites3 (id) deferrable,

  constraint identityproviders_c_id_gtz check (id_c > 0),
  constraint identityproviders_c_protocol check (protocol_c in ('oidc', 'oauth1', 'oauth2')),
  constraint identityproviders_c_syncmode check (sync_mode_c between 1 and 10),
  constraint identityproviders_c_alias_chars check (alias_c ~ '^[a-z0-9_-]+$'),
  constraint identityproviders_c_alias_len check (length(alias_c) between 1 and 50),
  constraint identityproviders_c_displayname_len check (length(display_name_c) between 1 and 200),
  constraint identityproviders_c_displayname_trim check (trim_all(display_name_c) = display_name_c),
  constraint identityproviders_c_description_c_len check (length(description_c) between 1 and 1000),
  constraint identityproviders_c_idpauthorizationurl_len check (length(idp_authorization_url_c) between 1 and 500),
  constraint identityproviders_c_idpaccesstokenurl_len check (length(idp_access_token_url_c) between 1 and 500),
  constraint identityproviders_c_idpaccesstokenauthmethod_in check (
      idp_access_token_auth_method_c in ('client_secret_basic', 'client_secret_post')),
  constraint identityproviders_c_idpuserinfourl_len check (length(idp_user_info_url_c) between 1 and 500),
  constraint identityproviders_c_idpuserinfofields_len check (length(idp_user_info_url_c) between 1 and 500),
  constraint identityproviders_c_idplogouturl_len check (length(idp_logout_url_c) between 1 and 500),
  constraint identityproviders_c_idpclientid_len check (length(idp_client_id_c) between 1 and 500),
  constraint identityproviders_c_idpclientsecret_len check (length(idp_client_secret_c) between 1 and 500),
  constraint identityproviders_c_idpissuer_len check (length(idp_issuer_c) between 1 and 200),
  constraint identityproviders_c_idpscopes_len check (length(idp_scopes_c) between 1 and 500),
  constraint identityproviders_c_idphosteddomain_len check (length(idp_hosted_domain_c) between 1 and 200)
);

create unique index identityproviders_u_protocol_alias on
    identity_providers_t (site_id_c, protocol_c, alias_c);

create unique index identityproviders_u_displayname on
    identity_providers_t (site_id_c, display_name_c);

