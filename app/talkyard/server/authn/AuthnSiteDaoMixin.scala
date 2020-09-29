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
import debiki.dao.{MemCacheKey, SiteDao}
import com.github.scribejava.core.oauth.{OAuth20Service => s_OAuth20Service}
import com.github.scribejava.core.builder.{ServiceBuilder => s_ServiceBuilder}




trait AuthnSiteDaoMixin {
  self: SiteDao =>



  // ----- Identity Providers


  def upsertIdentityProvider(identityProvider: IdentityProvider): AnyProblem = {
    COULD_OPTIMIZE // clear idp cache
    readWriteTransaction(_.upsertIdentityProvider(identityProvider))
  }


  def getIdentityProviderByAlias(protocol: St, alias: St): Option[IdentityProvider] = {
    COULD_OPTIMIZE // cache, use getIdentityProviders()
    readOnlyTransaction(_.loadIdentityProviderByAlias(protocol, alias))
  }


  def getIdentityProviderById(id: IdendityProviderId): Option[IdentityProvider] = {
    getIdentityProviders(onlyEnabled = false).find(_.id_c == id)
  }


  def getIdentityProviderNameFor(identity: OpenAuthDetails): Opt[St] = {
    identity.siteCustomIdpId match {
      case Some(id) =>
        // Race: Could be missing, if an admin removed the IDP just now.
        getIdentityProviderById(id).map(_.nameOrAlias)
      case None =>
        // Use the IDs defined by Silhouette, e.g. "google" or "facebook" lowercase :-|
        identity.serverDefaultIdpId
    }
  }


  def getIdentityProviders(onlyEnabled: Boolean): Seq[IdentityProvider] = {
    COULD_OPTIMIZE // cache
    val idps = loadAllIdentityProviders()
    if (onlyEnabled) idps.filter(_.enabled_c)
    else idps
  }


  def loadAllIdentityProviders(): Seq[IdentityProvider] = {
    readOnlyTransaction(_.loadAllIdentityProviders())
  }



  // ----- User Identities



  // ----- ScribeJava services


  def uncacheAuthnServices(idpsToUncache: Seq[IdentityProvider]): Unit = {
    // Later: Uncache only idpsToUncache (both by id, and by protocol + alias).
    memCache.remove(authnServicesKey)
  }


  def getAuthnService(origin: String, idp: IdentityProvider,
          mayCreate: Boolean = true): Option[s_OAuth20Service] = {

    val callbackUrl = origin + s"/-/authn/${idp.protocol_c}/${idp.alias_c}/callback"
    val scopes = idp.idp_scopes_c getOrElse "openid"  // or don't set if absent?

    // For now: Just one IDP. (If >= 2 used at the same time, one would get
    // uncached, login would fail.)
    val service = memCache.lookup(
          authnServicesKey,
          orCacheAndReturn = Some {
            new s_ServiceBuilder(idp.idp_client_id_c)
                  .apiSecret(idp.idp_client_secret_c)
                  .defaultScope(scopes)
                  .callback(callbackUrl)
                  .debug()
                  .build(TyOidcScribeJavaApi20(idp))
          },
          expireAfterSeconds = Some(3600)  // unimpl though — need a 2nd Coffeine cache? [mem_cache_exp_secs]
          ).get

    // It's the right IDP?
    if (service.getDefaultScope != scopes
        || service.getCallback != callbackUrl
        || service.getApiKey != idp.idp_client_id_c
        || service.getApiSecret != idp.idp_client_secret_c) {
      // It's the wrong. An admin recently changed OIDC settings?
      // Remove the old, create a new.
      uncacheAuthnServices(Seq(idp))
      if (!mayCreate)
        return None // no eternal recursion

      return getAuthnService(origin, idp, mayCreate = false)
    }

    Some(service)
  }



  private val authnServicesKey: MemCacheKey = MemCacheKey(siteId, "AzN")

}


