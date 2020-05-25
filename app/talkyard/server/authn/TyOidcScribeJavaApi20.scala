/**
 * Copyright (c) 2020 Kaj Magnus Lindberg
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package talkyard.server.authn

import com.debiki.core._
import com.debiki.core.Prelude._
import com.github.scribejava.core.builder.api.{DefaultApi20 => s_DefaultApi20}
import com.github.scribejava.core.extractors.{TokenExtractor => s_TokenExtractor}
import com.github.scribejava.core.model.{OAuth2AccessToken => s_OAuth2AccessToken}
import com.github.scribejava.apis.openid.{OpenIdJsonTokenExtractor => s_OpenIdJsonTokenExtractor}



private case class TyOidcScribeJavaApi20(idp: IdentityProvider) extends s_DefaultApi20 {

  // e.g.:  "http://keycloak:8080" + "/auth/realms/" + realm
  override def getAccessTokenEndpoint: String =
    idp.idp_access_token_url_c

  override def getAuthorizationBaseUrl: String =
    idp.idp_authorization_url_c

  override def getAccessTokenExtractor: s_TokenExtractor[s_OAuth2AccessToken] =
    s_OpenIdJsonTokenExtractor.instance

  /*
  val realmName = "talkyard_keycloak_test_realm"

  val oidcOpOrigin = "http://keycloak:8080"
  val odicOpConfUrlPath = s"/auth/realms/$realmName/.well-known/openid-configuration"
  val oidcOpConfUrl = s"$oidcOpOrigin$odicOpConfUrlPath"

  val redirectUrlPath = "/-/login-oidc/keycloak/callback"

  val userInfoUrl = s"$oidcOpOrigin/auth/realms/$realmName/protocol/openid-connect/userinfo"
   */
}

