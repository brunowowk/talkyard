
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
  idp_authorization_url_c varchar not null,
  idp_access_token_url_c varchar not null,
  idp_user_info_url_c varchar not null,
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
  -- Lowercase, because is lowercase in the url path.
  constraint identityproviders_c_protocol check (protocol_c in ('oidc', 'oauth1', 'oauth2')),
  constraint identityproviders_c_syncmode check (sync_mode_c between 1 and 10),
  -- Appears in urls.
  constraint identityproviders_c_alias_chars check (alias_c ~ '^[a-z0-9_-]+$'),
  constraint identityproviders_c_alias_len check (length(alias_c) between 1 and 50),
  constraint identityproviders_c_displayname_len check (length(display_name_c) between 1 and 200),
  constraint identityproviders_c_description_c_len check (length(description_c) between 1 and 1000),
  constraint identityproviders_c_opauthorizationurl_len check (length(idp_authorization_url_c) between 1 and 200),
  constraint identityproviders_c_opaccesstokenurl_len check (length(idp_access_token_url_c) between 1 and 200),
  constraint identityproviders_c_opuserinfourl_len check (length(idp_user_info_url_c) between 1 and 200),
  constraint identityproviders_c_oplogouturl_len check (length(idp_logout_url_c) between 1 and 200),
  constraint identityproviders_c_opclientid_len check (length(idp_client_id_c) between 1 and 200),
  constraint identityproviders_c_opclientsecret_len check (length(idp_client_secret_c) between 1 and 200),
  constraint identityproviders_c_opissuer_len check (length(idp_issuer_c) between 1 and 200),
  constraint identityproviders_c_opscopes_len check (length(idp_scopes_c) between 1 and 200),
  constraint identityproviders_c_ophosteddomain_len check (length(idp_hosted_domain_c) between 1 and 200)
);

create unique index identityproviders_u_protocol_alias on
    identity_providers_t (site_id_c, protocol_c, alias_c);

