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
import com.github.scribejava.core.builder.api.{DefaultApi20 => s_DefaultApi20}
import com.github.scribejava.core.extractors.{TokenExtractor => s_TokenExtractor}
import com.github.scribejava.core.model.{OAuth2AccessToken => s_OAuth2AccessToken}
import com.github.scribejava.apis.openid.{OpenIdJsonTokenExtractor => s_OpenIdJsonTokenExtractor}
import com.github.scribejava.core.oauth2.clientauthentication.{ClientAuthentication => s_ClientAuthentication, HttpBasicAuthenticationScheme => s_HttpBasicAuthenticationScheme, RequestBodyAuthenticationScheme => s_RequestBodyAuthenticationScheme}



private case class TyOidcScribeJavaApi20(idp: IdentityProvider) extends s_DefaultApi20 {

  // e.g.:  "http://keycloak:8080" + "/auth/realms/" + realm
  override def getAccessTokenEndpoint: String =
    idp.idp_access_token_url_c

  override def getAuthorizationBaseUrl: String =
    idp.idp_authorization_url_c

  override def getAccessTokenExtractor: s_TokenExtractor[s_OAuth2AccessToken] =
    s_OpenIdJsonTokenExtractor.instance

  override def getClientAuthentication: s_ClientAuthentication = {
    // See:  https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
    // Access method 'client_secret_post' includes this:
    // "...&client_id=...&client_secret=..."
    // in a form-data encoded request body. Whilst the other,
    // 'client_secret_basic', uses a Basic Auth HTTP header — that's better,
    // then, not in the post data, so is the default.
    /*
    if (idp.idp_access_token_auth_method_c == "client_secret_post")
      s_RequestBodyAuthenticationScheme.instance()
    else */
    s_HttpBasicAuthenticationScheme.instance()

    // There's also:
    // - client_secret_jwt  relies on HMAC SHA,
    // - private_key_jwt
    // - none (for Implicit Flow and public clients).
  }

}

