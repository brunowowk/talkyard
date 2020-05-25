package com.debiki.core

import com.debiki.core.IdentityProvider._
import com.debiki.core.Prelude._

object IdentityProvider {
  val ProtoNameOidc = "oidc"
  val ProtoNameOAuth2 = "oauth2"
}

case class IdentityProvider(
  id_c: IdendityProviderId,
  protocol_c: String,
  alias_c: String,
  enabled_c: Boolean,
  display_name_c: Option[String],
  description_c: Option[String],
  admin_comments_c: Option[String],
  trust_verified_email_c: Boolean,
  link_account_no_login_c: Boolean,
  gui_order_c: Option[Int],
  sync_mode_c: Int,  // for ow, always 1 = ImportOnFirstLogin, later, also: SyncOnAllLogins
  idp_authorization_url_c: String,
  idp_access_token_url_c: String,
  idp_access_token_auth_method_c: Opt[St] = None, // default: Basic Auth
  idp_user_info_url_c: String,
  idp_logout_url_c: Option[String],
  idp_client_id_c: String,
  idp_client_secret_c: String,
  idp_issuer_c: Option[String],
  idp_scopes_c: Option[String],
  idp_hosted_domain_c: Option[String],  // e.g. Google GSuite hosted domains
  idp_send_user_ip_c: Option[Boolean],  // so Google throttles based on the browser's ip instead
) {

  require(Seq(ProtoNameOidc, ProtoNameOAuth2).contains(protocol_c), "TyE306RKT")

  require(idp_access_token_auth_method_c.isEmpty ||
        idp_access_token_auth_method_c.is("client_secret_basic") ||
        idp_access_token_auth_method_c.is("client_secret_post"), "TyE305RKT2A3")

  def nameOrAlias: St = display_name_c getOrElse alias_c

  def isOpenIdConnect: Bo = protocol_c == ProtoNameOidc

}

