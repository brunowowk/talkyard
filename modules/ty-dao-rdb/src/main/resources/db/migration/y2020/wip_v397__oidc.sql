alter table settings3 add column enable_custom_idps boolean;
alter table settings3 add column use_only_custom_idps boolean;

alter table settings3 add constraint settings_c_enable_use_only_custom_idps check (
    (enable_custom_idps is not null and enable_custom_idps)
    or not use_only_custom_idps);

alter table settings3 add constraint settings_c_custom_idps_xor_sso check (
    not enable_custom_idps or not enable_sso);


-- Trims not just spaces, but all whitespace.
create or replace function trim_all(text character varying) returns varchar
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
  enabled_c bool not null,
  display_name_c varchar,
  description_c varchar,
  admin_comments_c varchar,
  trust_verified_email_c bool not null,
  link_account_no_login_c bool not null,
  gui_order_c int,
  sync_mode_c int not null,
  oidc_config_url varchar,
  idp_config_fetched_at timestamp,
  idp_config_edited_at timestamp,
  idp_config_json_c jsonb,
  idp_authorization_url_c varchar not null,
  idp_access_token_url_c varchar not null,
  idp_access_token_auth_method_c varchar,
  idp_user_info_url_c varchar not null,
  idp_user_info_fields_map_c jsonb,
  idp_logout_url_c varchar,
  idp_client_id_c varchar not null,
  idp_client_secret_c varchar not null,
  idp_issuer_c varchar,
  idp_scopes_c varchar,
  idp_hosted_domain_c varchar,
  idp_send_user_ip_c bool,

  constraint identityproviders_p_id primary key (site_id_c, id_c),

  -- fk ix: primary key index
  constraint identityproviders_r_sites foreign key (site_id_c)
      references sites3 (id) deferrable,

  constraint identityproviders_c_id_gtz check (id_c > 0),
  constraint identityproviders_c_protocol check (protocol_c in ('oidc', 'oauth1', 'oauth2')),
  constraint identityproviders_c_syncmode check (sync_mode_c between 1 and 10),
  constraint identityproviders_c_alias_chars check (alias_c ~ '^[a-z0-9_-]+$'),
  constraint identityproviders_c_alias_len check (length(alias_c) between 1 and 50),

  constraint identityproviders_c_displayname_len check (
      length(display_name_c) between 1 and 200),

  constraint identityproviders_c_displayname_trim check (
      trim_all(display_name_c) = display_name_c),

  constraint identityproviders_c_description_c_len check (
      length(description_c) between 1 and 1000),

  constraint identityproviders_c_admincomments_len check (
      length(admin_comments_c) between 1 and 5000),

  constraint identityproviders_c_oidcconfigurl_len check (
      length(oidc_config_url) between 1 and 500),

  constraint identityproviders_c_idpconfigjson_len check (
      pg_column_size(idp_config_json_c) between 1 and 11000),

  constraint identityproviders_c_idpauthorizationurl_len check (
      length(idp_authorization_url_c) between 1 and 500),

  constraint identityproviders_c_idpaccesstokenurl_len check (
      length(idp_access_token_url_c) between 1 and 500),

  constraint identityproviders_c_idpaccesstokenauthmethod_in check (
      idp_access_token_auth_method_c in (
          'client_secret_basic', 'client_secret_post')),

  constraint identityproviders_c_idpuserinfourl_len check (
      length(idp_user_info_url_c) between 1 and 500),

  constraint identityproviders_c_idpuserinfofieldsmap_len check (
      pg_column_size(idp_user_info_fields_map_c) between 1 and 3000),

  constraint identityproviders_c_idplogouturl_len check (
      length(idp_logout_url_c) between 1 and 500),

  constraint identityproviders_c_idpclientid_len check (
      length(idp_client_id_c) between 1 and 500),

  constraint identityproviders_c_idpclientsecret_len check (
      length(idp_client_secret_c) between 1 and 500),

  constraint identityproviders_c_idpissuer_len check (
      length(idp_issuer_c) between 1 and 200),

  constraint identityproviders_c_idpscopes_len check (
      length(idp_scopes_c) between 1 and 500),

  constraint identityproviders_c_idphosteddomain_len check (
      length(idp_hosted_domain_c) between 1 and 200)
);


create unique index identityproviders_u_protocol_alias on
    identity_providers_t (site_id_c, protocol_c, alias_c);

create unique index identityproviders_u_displayname on
    identity_providers_t (site_id_c, display_name_c);



alter table identities3 add column site_custom_idp_id_c int;
alter table identities3 add column idp_user_id_c varchar;
alter table identities3 add column idp_user_info_json_c jsonb; -- ren to just ..user_json?

-- alter table identities3 add column oidc_id_token_str varchar;
-- alter table identities3 add column oidc_id_token_json jsonb;

-- alter table identities3 drop column site_custom_idp_id_c;
-- alter table identities3 drop column idp_user_id_c ;
-- alter table identities3 drop column idp_user_info_json_c ;


-- fk ix: identities_u_idpid_idpuserid
alter table identities3 add constraint identities_r_idps
    foreign key (site_id, site_custom_idp_id_c)
    references identity_providers_t (site_id_c, id_c) deferrable;

alter table identities3 add constraint identities_c_idpuserid_len check (
    length(idp_user_id_c) between 1 and 500);

alter table identities3 add constraint identities_c_userinfojson_len check (
    pg_column_size(idp_user_info_json_c) between 1 and 7000);

-- RENAME  securesocial_provider_id  to server_default_idp_id_c  ?
alter table identities3 add constraint identities_c_one_type check (
    num_nonnulls(oid_claimed_id, site_custom_idp_id_c, securesocial_provider_id)
        = 1);

alter table identities3 add constraint identities_c_customidp_idpuserid check (
    (site_custom_idp_id_c is null) = (idp_user_id_c is null));

alter table identities3 add constraint identities_c_customidp_idpuserinfo check (
    (site_custom_idp_id_c is not null) or (idp_user_info_json_c is null));

create unique index identities_u_idpid_idpuserid on
    identities3 (site_id, site_custom_idp_id_c, idp_user_id_c)
    where site_custom_idp_id_c is not null;
