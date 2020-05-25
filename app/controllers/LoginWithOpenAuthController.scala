/**
 * Copyright (c) 2014-2017, 2020 Kaj Magnus Lindberg
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

package controllers

import com.debiki.core._
import com.debiki.core.Prelude._
import com.github.benmanes.caffeine
import com.github.scribejava.core.oauth.{OAuth20Service => s_OAuth20Service}
import com.github.scribejava.core.model.{OAuth2AccessToken => s_OAuth2AccessToken, OAuth2AccessTokenErrorResponse => s_OAuth2AccessTokenErrorResponse, OAuthAsyncRequestCallback => s_OAuthAsyncRequestCallback, OAuthRequest => s_OAuthRequest, Response => s_Response, Verb => s_Verb}
import com.github.scribejava.apis.openid.{OpenIdOAuth2AccessToken => s_OpenIdOAuth2AccessToken}
import com.mohiva.play.silhouette
import com.mohiva.play.silhouette.api.util.HTTPLayer
import com.mohiva.play.silhouette.api.LoginInfo
import com.mohiva.play.silhouette.impl.providers.oauth1.services.PlayOAuth1Service
import com.mohiva.play.silhouette.impl.providers.oauth1.TwitterProvider
import com.mohiva.play.silhouette.impl.providers.oauth2._
import com.mohiva.play.silhouette.impl.providers._
import ed.server.spam.SpamChecker
import debiki._
import debiki.EdHttp._
import ed.server._
import ed.server.http._
import ed.server.security.EdSecurity
import java.io.{IOException => j_IOException}
import java.util.concurrent.{ExecutionException => j_ExecutionException}

import debiki.dao.SiteDao
import javax.inject.Inject
import org.scalactic.{Bad, ErrorMessage, Good, Or}
import play.api.libs.json._
import play.api.mvc._
import play.api.Configuration
import talkyard.server.authn.{parseCustomUserInfo, parseOidcUserInfo}

import scala.concurrent.{ExecutionContext, Future, Promise}
import scala.concurrent.duration._
import scala.util.{Failure, Success}
import talkyard.server.{ProdConfFilePath, TyLogging}



case class OAuth2StateStruct(
  stateStringDebug: String,
  returnToUrl: String,
  browserXsrfToken: String,
  createdAt: When,
  useCount: java.util.concurrent.atomic.AtomicInteger)



/** OpenAuth 1 and 2 login, provided by Silhouette, e.g. for Google, Facebook and Twitter.
  *
  * This class is a bit complicated, because it supports logging in at site X
  * via another site, say login.domain.com. This is needed because Debiki is a multitenant
  * system, but OAuth providers allow one to login only via *one* single domain. That
  * single domain is login.domain.com, and if you want to login at site X this class
  * redirects you to login.domain.com, then logs you in at the OAuth provider from
  * login.domain.com, and redirects you back to X with a session id and an XSRF token.
  */
class LoginWithOpenAuthController @Inject()(cc: ControllerComponents, edContext: EdContext)
  extends EdController(cc, edContext) with TyLogging {

  REFACTOR // MOVE this file to package talkyard.server.authn
  REFACTOR // Split into   AuthnController  and  OldAuthnControllerSilhouette  ?

  import context.globals
  import context.security._

  private val LoginTimeoutMins = 15
  private val Separator = '|'

  private val ReturnToUrlCookieName = "dwCoReturnToUrl"
  private val ReturnToSiteOriginTokenCookieName = "dwCoReturnToSite"
  private val ReturnToThisSiteXsrfTokenCookieName = "dwCoReturnToSiteXsrfToken"
  private val AvoidCookiesCookieName = "TyCoAvoidCookies"
  private val IsInLoginWindowCookieName = "dwCoIsInLoginWindow"
  private val IsInLoginPopupCookieName = "dwCoIsInLoginPopup"
  private val MayCreateUserCookieName = "dwCoMayCreateUser"
  private val AuthStateCookieName = "dwCoOAuth2State"

  private val CookiesToDiscardAfterLogin: Seq[DiscardingCookie] = Seq(
    ReturnToUrlCookieName,
    ReturnToSiteOriginTokenCookieName,
    ReturnToThisSiteXsrfTokenCookieName,
    AvoidCookiesCookieName,
    IsInLoginWindowCookieName,
    IsInLoginPopupCookieName,
    MayCreateUserCookieName,
    AuthStateCookieName).map(DiscardingSecureCookie)

  def conf: Configuration = globals.rawConf

  private val extIdentityCache = caffeine.cache.Caffeine.newBuilder()
    .maximumSize(20*1000) // change to config value, e.g. 1e9 = 1GB mem cache. Default to 50M? [ADJMEMUSG]
    // Don't expire too quickly — the user needs time to choose & typ a username.
    // SECURITY COULD expire sooner (say 10 seconds) if just logging in, because then
    // the user need not think or type anything.
    // The user might want to review the Terms of Use, so wait for an hour, here. [4WHKTP06]
    // BUG SHOULD use Redis, so the key won't disappear after server restart.
    .expireAfterWrite(65, java.util.concurrent.TimeUnit.MINUTES)
    .build().asInstanceOf[caffeine.cache.Cache[String, OpenAuthDetails]]

  // Maps OAuth2 state to (created-at, return-to-URL, use-count).
  // And if one attempts to use the state after (
  private val oauth2StateCache = caffeine.cache.Caffeine.newBuilder()
        .maximumSize(20*1000) // change to config value, e.g. 1e9 = 1GB mem cache. Default to 50M? [ADJMEMUSG]
        // BUG COULD use Redis, so the key won't disappear after server restart.
        .expireAfterWrite(65, java.util.concurrent.TimeUnit.MINUTES)
        .build().asInstanceOf[caffeine.cache.Cache[String, OAuth2StateStruct]]

  private val linkAccountsCache = caffeine.cache.Caffeine.newBuilder()
        .maximumSize(1000)
        .expireAfterWrite(
             MaxEmailSecretLinkAgeMinutes, java.util.concurrent.TimeUnit.MINUTES)
        .build().asInstanceOf[caffeine.cache.Cache[String, (OpenAuthDetails, User)]]


  private case class StateAndNonce(browserIdOrEmpty: String, nonce: String)


  /*
  private val oidcProviderMetadataByConfigUrl = caffeine.cache.Caffeine.newBuilder()
    // 2000 sites with OIDC enabled on this server is a lot
    .maximumSize(2000)
    // Let's refresh daily? Caching forever would be ok too.
    .expireAfterWrite(24, java.util.concurrent.TimeUnit.HOURS)
    .build().asInstanceOf[caffeine.cache.Cache[String, AnyRef]]  // n_OIDCProviderMetadata
    */

  private val oidcStateNonceCache = caffeine.cache.Caffeine.newBuilder()
    .maximumSize(20*1000) // [ADJMEMUSG]
    .expireAfterWrite(65, java.util.concurrent.TimeUnit.MINUTES) // [4WHKTP06]
    .build().asInstanceOf[caffeine.cache.Cache[String, StateAndNonce]]



  def authnStart(protocol: String, providerAlias: String,
          returnToUrl: String, loginXsrfToken: String): Action[Unit]
          = AsyncGetActionIsLogin { request =>
      authnStartImpl(protocol, providerAlias, returnToUrl = returnToUrl,
            loginXsrfToken = loginXsrfToken, request)
    }


  private def authnStartImpl(protocol: String, providerAlias: String,
        returnToUrl: String, loginXsrfToken: String,
        request: GetRequest): Future[Result] = {

    import request.{dao, siteId}

    protocol match {
      case "oidc" | "oauth2" =>  // lowercase, from the url
      case _ => throwNotFound("TyEBADPROTO", "TyE603RFKEGM")
    }

    // Once done logging in, the browser will look for this value in the
    // url, and, if absent, could mean a login xsrf attack is happening
    // — then, better reject the login session (which might be an attacker's
    // session, not the real end user's session).
    val browsersLoginXsrfToken =
          if (loginXsrfToken.nonEmpty) {
            loginXsrfToken
          }
          else {
            urlDecodeCookie(EdSecurity.XsrfCookieName, request.underlying)
                  .getOrThrowBadRequest(
                      "TyE0LOGINXSRF", "Browse login XSRF token not specified")
          }

    val idp: IdentityProvider =
          dao.getIdentityProviderByAlias(protocol, providerAlias) getOrElse {
      // For now:
      throwForbidden("TyE6RKT0456", s"No $protocol provider with alias: '$providerAlias'")

      /*
      if (globals.anyLoginOrigin isSomethingButNot originOf(request)) {
        // OAuth providers have been configured to send authentication data to
        // anyLoginOrigin.get. We'll redirect to that origin, login there, and it'll
        // send the user back here.
        return loginViaLoginOrigin(providerAlias, request.underlying)
      } */
    }

    // Is it ok to reveal that this provider exists? Otherwise could be really
    // confusing to troubleshoot this.  There could be another setting:
    // hide: Boolean  or  hideIfDisabled: Boolean,
    // if Ty should try to not show that it even exists?
    throwForbiddenIf(!idp.enabled_c, "TyEIDPDISBLD",
          s"Identity provider $providerAlias, protocol $protocol, is disabled")

    val origin =
          if (Globals.isProd || request.isDevTestToToLocalhost) {
            request.origin
          }
          else {
            // We're testing authn against an external service?
            // For now, pretend we use https.
            request.origin.replaceAllLiterally("http:", "https:")
          }

    val authnService: s_OAuth20Service = dao.getAuthnService(origin, idp) getOrElse {
      throwInternalError("TyEMAKEIDPSVC01",
            s"s$siteId: Cannot get/create ScribeJava service for '$providerAlias'")
    }

    val stateString = nextRandomString()

    val stateStruct = OAuth2StateStruct(
      stateStringDebug = stateString,
      returnToUrl = returnToUrl,
      browserXsrfToken = browsersLoginXsrfToken,
      createdAt = globals.now(),
      useCount = new java.util.concurrent.atomic.AtomicInteger(0))

    oauth2StateCache.put(stateString, stateStruct)

    val authorizationUrl: String = authnService.createAuthorizationUrlBuilder()
          .state(stateString)
          //.additionalParams(... identity provider specific  &query = params ...)
          .build()

    // Redirect the browser to the OAuth2 auth endpoint, to login over there.
    Future.successful(
          play.api.mvc.Results.Redirect(
              authorizationUrl, status = play.api.http.Status.SEE_OTHER))
  }


  /** (IDP = identity provider.)
    *
    * Note that the IDP might be mallicious (so, need rate limits, for example),
    * and that the end user might be someone clicking an attacker provided link.
    *
    * @param state — specified by Ty. For preventing xsrf attacks.
    * @param session_state — if the IDP, say, Keycloak, supports
    *  session management (like, logout?), it'll include a &session_state=...
    *  query param. Talkyard can then include this param in all subsequent
    *  requests to the IDP, so that the IDP knows which user Talkyard has
    *  in mind, from the IDP:s point of view. And (?) if Ty tells the IDP that
    *  the user has logged out, then the IDP can log the user out from other
    *  services (other than Ty) managed by the IDP too  ?
    * @param code — the authorization code, a temporary code to send
    *  to the OAuth2 server, to get back an access token.
    * @return Redirects the browser to some Talkyard page, or possibly
    *  embedding website with embedded comments / an embedded Ty forum.
    */
  def authnCallback(protocol: String, providerAlias: String,
          state: String, session_state: Option[String], code: String): Action[Unit]
          = AsyncGetActionIsLoginRateLimited { request =>

    import request.{dao, siteId}

    logger.debug(i"""
          |s$siteId: OAuth2 redir back:
          |  State: $state
          |  Code: $code
          |  Session state: $session_state""")

    val stateStruct: OAuth2StateStruct =
          Option(oauth2StateCache.getIfPresent(state))
              .getOrThrowBadRequest("TyEOAUSTATEBAD", s"No such OAuth2 state: $state")

    logger.debug(s"s$siteId: State struct: $stateStruct\n")
    dieIf(stateStruct.stateStringDebug != state, "TyE3M06KD24")

    val usageCount = stateStruct.useCount.incrementAndGet()
    if (usageCount >= 2) {
      throwForbidden("TyEOAUSTATEUSED",
            s"Trying to use one-time OAuth2 redirect-back-URI $usageCount times")
    }

    // Give the user a few minutes to login — maybe hen wants to read some
    // Terms of Use or Privacy Policy.
    // If too slow, show a somewhat user friendly please-try-again message.
    val minutesOld = globals.now().minutesSince(stateStruct.createdAt)
    val maxMins = 5
    if (minutesOld > maxMins) {
      throwForbidden("TyEOAUSTATESLOW",
            o"""You need to login within $maxMins minutes. Try again, a bit faster?
              Time elapsed: $minutesOld minutes.""")
    }

    val idp: IdentityProvider = request.dao.getIdentityProviderByAlias(
          protocol, providerAlias) getOrElse {
      // if  is login origin   fine, use config file default login settings
      // else
      //   return forbidden
      // For now:
      throwForbidden("TyE5026KSH5",
            s"Bad protocol: '$protocol' or IDP provider alias: '$providerAlias'")
    }

    val origin =
          if (Globals.isProd || request.isDevTestToToLocalhost) {
            request.origin
          }
          else {
            // We're testing authn against an external service?
            // For now, pretend we use https.
            request.origin.replaceAllLiterally("http:", "https:")
          }

    // ----- Access token request

    // We got back `code`, a temporary authorization code, from the auth server,
    // via the query string in the browser, when it got redirected back to Ty.
    // All we can do with this temp code, is to send it to the auth server,
    // to get an access token.  (Later, we'll use the access token
    // to retrieve user info from the auth server.)
    //
    // The reason for this "extra" temp code step, is that 1) `code` is seen
    // by the browser / end-user-app, and possibly intermediate infrastructure,
    // when the browser is redirected back to the Ty server (the `code`
    // is in the URL). So, it might get intercepted by an attacker.
    // And 2) the IDP wants to authenticate the Talkyard server (so the IDP
    // won't send access tokens to untrusted servers).
    //
    // Therefore, the OAuth2 code flow requires the Ty server to send
    // the code together with the IDP client secret to the auth server,
    // in a separate backchannel request, to get the real access token.
    //
    // See https://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
    // and https://www.oauth.com/oauth2-servers/access-tokens/authorization-code-request/

    val authnService: s_OAuth20Service = dao.getAuthnService(origin, idp) getOrElse {
      throwInternalError("TyEMAKEIDPSVC02",
            s"s$siteId: Cannot get/create ScribeJava service for '$providerAlias'")
    }

    val idAndAccessTokenPromise =
          Promise[(s_OpenIdOAuth2AccessToken, Opt[OidcIdToken])]()

    authnService.getAccessToken(code, new s_OAuthAsyncRequestCallback[s_OAuth2AccessToken] {
      override def onCompleted(tokensParentClass: s_OAuth2AccessToken): Unit = {
        // TyOidcScribeJavaApi20 uses OpenIdJsonTokenExtractor.instance
        // as access token extractor; therefore, we can downcast to
        // OpenIdOAuth2AccessToken.
        val tokens = tokensParentClass match {
          case t: s_OpenIdOAuth2AccessToken => t
          case bad =>
            die("TyE3M05ATJ4", s"Bad class: ${classNameOf(bad)}, value: $bad")
        }

        // If this is some custom OAuth2 implementation, with no OIDC
        // id_token, then, tokens.openIdToken  is null here — fine.
        // However if the protocol *is* OIDC, then:
        var anyIdToken: Opt[OidcIdToken] = None
        if (idp.isOpenIdConnect) {
          val idTokenStr = tokens.getOpenIdToken
          if (idTokenStr eq null) {
            idAndAccessTokenPromise.failure(new QuickMessageException(
                  s"Token response from OIDC provider has no id_token: ${
                      tokens} [TyEACSTKNRSP0IDTKN]"))
            return
          }

          anyIdToken = Some(new OidcIdToken(idTokenStr))

          // https://openid.net/specs/openid-connect-basic-1_0.html#IDToken
          SECURITY; SHOULD // check ID token nonce:
          // nonce:  case-sensitive string
          //    OPTIONAL. String value used to associate a Client session with
          //    an ID Token, and to mitigate replay attacks.
          //    The value is passed through unmodified from the Authentication Request
          //    to the ID Token. The Client MUST verify that the nonce Claim Value
          //    is equal to the value of the nonce parameter sent in the
          //    Authentication Request. If present in the Authentication Request,
          //    Authorization Servers MUST include a nonce Claim in the ID Token
          //    with the Claim Value being the nonce value sent in the
          //    Authentication Request.
        }
        idAndAccessTokenPromise.success((tokens, anyIdToken))
      }
      override def onThrowable(t: Throwable): Unit = {
        idAndAccessTokenPromise.failure(t)
      }
    })

    val userInfoPromise = Promise[(s_Response, Opt[OidcIdToken])]()

    idAndAccessTokenPromise.future.onComplete({
      case Failure(throwable: Throwable) =>
        val errorResponseException = throwable match {
          case ex @ (_: InterruptedException | _: j_ExecutionException | _: j_IOException) =>
            // We din't even get a response!
            ResultException(InternalErrorResult("TyEACSTKNREQ",
                  s"Error requesting access token: ${ex.toString}"))
          case ex: s_OAuth2AccessTokenErrorResponse =>
            // We got an Error response.
            ResultException(ForbiddenResult("TyEACSTKNRSP",
                  s"Error response from access token endpoint: ${ex.toString}"))
          case ex: Exception =>
            ResultException(InternalErrorResult("TyEACSTKNUNK",
                  s"Unknown error requesting access token: ${ex.toString}"))
        }
        // Pass our response on to userInfoPromise — it replies to the browser.
        userInfoPromise.failure(errorResponseException)

      case Success((tokens: s_OpenIdOAuth2AccessToken, anyIdToken)) =>
        // Continue below.
        requestUserInfo(tokens, anyIdToken)
    })


    // ----- User info request

    // Now we have the access token (hopefully), and with it we can do
    // anything we requested in the  &scope=...  parameter in the initial
    // browser auth redirect to the auth server, and that the user accepted.
    //
    // All we want to do, though, is to fetch some user info data.
    // So, we'll call the user info endpoint.  And we'll include the access
    // token, so the auth server won't just reply Forbidden.

    def requestUserInfo(tokens: s_OpenIdOAuth2AccessToken, idToken: Opt[OidcIdToken]) {
      val userInfoRequest = new s_OAuthRequest(s_Verb.GET, idp.idp_user_info_url_c)
      authnService.signRequest(tokens, userInfoRequest)

      authnService.execute(userInfoRequest, new s_OAuthAsyncRequestCallback[s_Response] {
        override def onCompleted(response: s_Response): Unit = {
          userInfoPromise.success((response, idToken))
        }
        override def onThrowable(t: Throwable): Unit = {
          userInfoPromise.failure(t)
        }
      })
    }

    val futureResponseToBrowser = userInfoPromise.future.transform {
      case Failure(throwable: Throwable) =>
        val errorResponse = throwable match {
          case ResultException(response) =>
            // This happens if the access token request failed, above.
            Success(response)
          case ex@(_: InterruptedException | _: j_ExecutionException | _: j_IOException) =>
            Success(InternalErrorResult(
                  "TyEUSRINFREQ", s"Error requesting user info: ${ex.toString}"))
          case ex =>
            Success(InternalErrorResult(
                  "TyEUSRINFUNK", s"Unknown error requesting user info: ${ex.toString}"))
        }
        errorResponse

      case Success((userInfoResponse: s_Response, anyIdToken: Opt[OidcIdToken])) =>
        val responseToBrowser = handleUserInfoResponse(
              request, idp, userInfoResponse, anyIdToken,
              returnToUrl = stateStruct.returnToUrl)
        Success(responseToBrowser)
    }

    futureResponseToBrowser
  }


  private def handleUserInfoResponse(request: GetRequest, idp: IdentityProvider,
          userInfoResponse: s_Response, anyIdToken: Opt[OidcIdToken],
          returnToUrl: St): Result = {
    import request.siteId
    val httpStatusCode = userInfoResponse.getCode
    val body = userInfoResponse.getBody

    if (httpStatusCode < 200 || 299 < httpStatusCode) {
      val randVal = nextRandomString()
      val errCode = "TyEUSRINFRSP"

      logger.warn(i"""s$siteId: Bad OIDC/OAuth2 userinfo response [$errCode],
          |Log message random id: '$randVal'
          |IDP alias: ${idp.alias_c}, Ty db id: ${idp.id_c}
          |Browser redir-back request URL: ${request.uri}
          |IDP response status code: $httpStatusCode  (bad, not 2XX)
          |IDP response body: -----------------------
          |$body
          |--------------------------------------
          |""")
      return InternalErrorResult(errCode, o"""Unexpected status code:
            $httpStatusCode, see logs for details, search for '$randVal'""")
    }

    val maxUserRespLen = 5*1000
    if (body.length > maxUserRespLen) {
      // This is a weird IDP!?
      return ForbiddenResult(
            "TyEUSRINF2LONG", o"""Too long JSON payload: ${body.length
                  } chars, max is: $maxUserRespLen""")
    }

    val json =
          try Json.parse(body)
          catch {
            case ex: Exception =>
              return ForbiddenResult(
                    "TyEUSRINFJSONPARSE", s"Malformed JSON from userinfo endpoint")
          }

    import IdentityProvider.{ProtoNameOidc, ProtoNameOAuth2}
    var oauthDetails: OpenAuthDetails = (idp.protocol_c match {
      case ProtoNameOidc => parseOidcUserInfo(json, idp)
      case ProtoNameOAuth2 => parseCustomUserInfo(json, idp)
      case x => die("TyE5F5RKS56", s"Bad auth protocol: $x")
    }) getOrIfBad { errMsg =>
      return BadReqResult("TyEUSRINFJSONUSE", errMsg)
    }

    anyIdToken foreach { idToken: OidcIdToken =>
      oauthDetails = oauthDetails.copy(oidcIdToken = Some(idToken))
    }

    tryLoginOrShowCreateUserDialog(
          request, anyOauthDetails = Some(oauthDetails), anyCustomIdp = Some(idp),
          anyReturnToUrl = Some(returnToUrl))
    /*
    val message = s"Response body:\n\n$body\nConstructed profile: $profile\n"
    logger.debug(s"s$siteId: $message")
    Ok(message)
     */
  }


  def authnLogout(): Action[Unit] = AsyncGetActionIsLogin { request =>
    Future.successful(NotImplementedResult("TyEOIDCLGO", "Not implemented"))
    // TODO backchannel logout from  /-/logout ?
  }




  // ======================================================================
  //   Old, with Silhouette   =============================================
  // ======================================================================


  def startAuthentication(providerName: String, returnToUrl: String): Action[Unit] =
        AsyncGetActionIsLogin { request =>
    startAuthenticationImpl(providerName, returnToUrl, request)
  }


  private def startAuthenticationImpl(providerName: String, returnToUrl: String,
        request: GetRequest): Future[Result] = {

    globals.loginOriginConfigErrorMessage foreach { message =>
      throwInternalError("DwE5WKU3", message)
    }

    var futureResult = startOrFinishAuthenticationWithSilhouette(providerName, request)
    if (returnToUrl.nonEmpty) {
      futureResult = futureResult map { result =>
        result.withCookies(
          // CLEAN_UP use OAuth2 state instead? skip the cookie.
          // That's how the new OIDC code (above) works instead, already.
          // Can save the returnToUrl in mem cache, also if redirs to login origin?
          SecureCookie(name = ReturnToUrlCookieName, value = returnToUrl, httpOnly = false))
      }
    }
    if (request.rawQueryString.contains("isInLoginPopup")) {
      futureResult = futureResult map { result =>
        result.withCookies(
          SecureCookie(name = IsInLoginPopupCookieName, value = "true", httpOnly = false))
      }
    }
    if (request.rawQueryString.contains("mayNotCreateUser")) {
      futureResult = futureResult map { result =>
        result.withCookies(
          SecureCookie(name = MayCreateUserCookieName, value = "false", httpOnly = false))
      }
    }
    futureResult
  }


  def finishAuthentication(providerName: String): Action[Unit] =
        AsyncGetActionIsLogin { request =>
    startOrFinishAuthenticationWithSilhouette(providerName, request)
  }


  /** Authenticates a user against e.g. Facebook or Google or Twitter, using OAuth 1 or 2.
    *
    * Confusingly enough (?), Silhouette uses the same method both for starting
    * and finishing authentication. (529JZ24)
    *
    * Based on:
    *   https://github.com/mohiva/play-silhouette-seed/blob/master/
    *                     app/controllers/SocialAuthController.scala#L32
    */
  private def startOrFinishAuthenticationWithSilhouette(
        providerName: String, request: GetRequest): Future[Result] = {
    context.rateLimiter.rateLimit(RateLimits.Login, request)

    val settings = request.siteSettings

    throwForbiddenIf(settings.enableSso,
      "TyESSO0OAUTH", "OpenAuth authentication disabled, because SSO enabled")
    throwForbiddenIf(settings.useOnlyCustomIdps,
      "TyECUIDPDEFOAU", o"""Default OpenAuth authentication disabled,
        when using only custom OIDC or OAuth2""")

    if (globals.anyLoginOrigin isSomethingButNot originOf(request)) {
      // OAuth providers have been configured to send authentication data to another
      // origin (namely anyLoginOrigin.get); we need to redirect to that origin
      // and login from there.
      return loginViaLoginOrigin(providerName, request.underlying)
    }

    val provider: SocialProvider = providerName match {   // with TalkyardSocialProfileBuilder?  (TYSOCPROF)
      case FacebookProvider.ID =>
        throwForbiddenIf(!settings.enableFacebookLogin, "TyE0FBLOGIN", "Facebook login disabled")
        facebookProvider()
      case GoogleProvider.ID =>
        throwForbiddenIf(!settings.enableGoogleLogin, "TyE0GOOGLOGIN", "Google login disabled")
        googleProvider()
      case TwitterProvider.ID =>
        throwForbiddenIf(!settings.enableTwitterLogin, "TyE0TWTTRLOGIN", "Twitter login disabled")
        twitterProvider()
      case GitHubProvider.ID =>
        throwForbiddenIf(!settings.enableGitHubLogin, "TyE0GITHLOGIN", "GitHub login disabled")
        githubProvider()
      case GitLabProvider.ID =>
        throwForbiddenIf(!settings.enableGitLabLogin, "TyE0GITLBLOGIN", "GitLab login disabled")
        gitlabProvider()
      case LinkedInProvider.ID =>
        throwForbiddenIf(!settings.enableLinkedInLogin, "TyE0LKDINLOGIN", "LinkedIn login disabled")
        linkedinProvider()
      case VKProvider.ID =>
        throwForbiddenIf(!settings.enableVkLogin, "TyE0VKLOGIN", "VK login disabled")
        vkProvider()
      case InstagramProvider.ID =>
        throwForbiddenIf(!settings.enableInstagramLogin, "TyE0INSTALOGIN", "Instagram login disabled")
        instagramProvider()
      case x =>
        return Future.successful(Results.Forbidden(s"Bad provider: `$providerName' [DwE2F0D6]"))
    }

    UX; COULD // handle 429 resource exhausted from an OAuth provider in a better way?:
    //  {"severity":"ERROR","context":{"reportLocation":{"filePath":
    //  "LoginWithOpenAuthController.scala","lineNumber":223, "functionName":"applyOrElse","className":
    //    "controllers.LoginWithOpenAuthController$$anonfun$startOrFinishAuthenticationWithSilhouette$14"}},
    //    "message":"Error during OAuth2 authentication with Silhouette [TYE0AUUNKN]
    //       \ncom.mohiva.play.silhouette.impl.exceptions.ProfileRetrievalException:
    //       [Silhouette][google] Error retrieving profile information.
    //      Error code: 429, message: Resource has been exhausted (e.g. check quota).
    //      \n\tat com.mohiva.play.silhouette.impl.providers.oauth2.BaseGoogleProvider
    //         .$anonfun$buildProfile$1(GoogleProvider.scala:69)\n\tat  ... }

    provider.authenticate()(request.request) flatMap {  // (529JZ24)
      case Left(result) =>
        // We're starting authentication.
        Future.successful(result)
      case Right(authInfo) =>
        // We're finishing authentication.
        val futureProfile: Future[SocialProfile] = provider.retrieveProfile(authInfo)
        futureProfile flatMap { profile: SocialProfile =>   // TalkyardSocialProfile?  (TYSOCPROF)
          Future.successful(
                handleAuthenticationData(request, profile))
        }
    } recoverWith {
      case ex: Exception =>
        val noStateHandlerMessage: String =
          com.mohiva.play.silhouette.impl.providers.DefaultSocialStateHandler.MissingItemHandlerError
            .dropRight(5)  // trop trailing  %s
        // Silhouette has an xsrf cookie 5 minutes timeout, and overwrites (forgets) old handlers
        // if one clicks login buttons in different browser tabs, in parallel. [PRLGIN]
        val handlerMissing = ex.getMessage.contains(noStateHandlerMessage)
        val result =
          if (handlerMissing) {
            logger.warn(s"Silhouette handler missing error [TYEOAUTMTPLL2]", ex)
            BadReqResult("TYEOAUTMTPLL", "\nYou need to login within 5 minutes, and " +
              "you cannot login in different browser tabs, at the same time. Error logging in.")
          }
          else {
            val errorCode = "TYE0AUUNKN"
            logger.error(s"Error during OAuth2 authentication with Silhouette [$errorCode]", ex)
            import org.apache.commons.lang3.exception.ExceptionUtils.getStackTrace
            InternalErrorResult(errorCode, "Unknown login error", moreDetails =
              s"Error when signing in with $providerName: ${ex.getMessage}\n\n" +
              "Stack trace:\n" + getStackTrace(ex))
          }
        Future.successful(result)
    }
  }


  private def handleAuthenticationData(request: GetRequest, profile: SocialProfile)
        : Result = {
    logger.debug(s"OAuth data received at ${originOf(request)}: $profile")

    val (anyReturnToSiteOrigin: Option[String], anyReturnToSiteXsrfToken: Option[String]) =
      request.cookies.get(ReturnToSiteOriginTokenCookieName) match {
        case None => (None, None)
        case Some(cookie) =>
          val (originalSiteOrigin, separatorAndXsrfToken) = cookie.value.span(_ != Separator)
          (Some(originalSiteOrigin), Some(separatorAndXsrfToken.drop(1)))
      }

    val anyReturnToUrl = request.cookies.get(ReturnToUrlCookieName).map(_.value)

    if (anyReturnToSiteOrigin.isDefined && anyReturnToUrl.isDefined) {
      // Someone has two browser tabs open? And in one tab s/he attempts to login at one site,
      // and in another tab at the site at anyLoginDomain? Don't know which login attempt
      // to continue with.
      val errorMessage = i"""Parallel logins not supported. Cookies now cleared. Try again. [EdE07G32]
        |
        |Details: Both these were defined:
        |anyReturnToSiteOrigin = $anyReturnToSiteOrigin
        |anyReturnToUrl = $anyReturnToUrl"""
      // Delete the cookies, so if the user tries again, there'll be only one cookie and things
      // will work properly.
      return Forbidden(errorMessage).discardingCookies(
          DiscardingSecureCookie(ReturnToSiteOriginTokenCookieName),
          DiscardingSecureCookie(ReturnToUrlCookieName))
    }

    REFACTOR; CLEAN_UP // stop using CommonSocialProfile. Use ExternalSocialProfile instead,  (TYSOCPROF)
    // it has useful things like username, about user text, etc.
    var oauthDetails = profile match {
      case p: CommonSocialProfile =>
        OpenAuthDetails(
          serverDefaultIdpId = Some(p.loginInfo.providerID),
          idpUserId = p.loginInfo.providerKey,
          username = None, // not incl in CommonSocialProfile
          firstName = p.firstName,
          lastName = p.lastName,
          fullName = p.fullName,
          email = p.email,
          avatarUrl = p.avatarURL)
      case p: ExternalSocialProfile =>
        OpenAuthDetails(
          serverDefaultIdpId = Some(p.providerId),
          idpUserId = p.providerUserId,
          username = p.username,
          firstName = p.firstName,
          lastName = p.lastName,
          fullName = p.fullName,
          email = if (p.primaryEmailIsVerified is true) p.primaryEmail else None,  // [7KRBGQ20]
          avatarUrl = p.avatarUrl)
    }

    // Don't know about Facebook and GitHub. Twitter has no emails at all.
    // We currently use only verified email addresses, from GitHub. [7KRBGQ20]
    // Gmail addresses have been verified by Google.
    // Facebook? Who knows what they do.
    // LinkedIn: Don't know if the email has been verified; exclude LinkedIn here.
    if ((oauthDetails.serverDefaultIdpId.is(GoogleProvider.ID) &&
            oauthDetails.email.exists(_ endsWith "@gmail.com"))
        || oauthDetails.serverDefaultIdpId.is(GitHubProvider.ID)) {
      oauthDetails = oauthDetails.copy(isEmailVerifiedByIdp = Some(true))
      COULD // include  [known_verified_email_domains]  too.
    }

    val result = anyReturnToSiteOrigin match {
      case Some(originalSiteOrigin) =>
        val xsrfToken = anyReturnToSiteXsrfToken getOrDie "DwE0F4C2"
        val oauthDetailsCacheKey = nextRandomString()
        SHOULD // use Redis instead, so logins won't fail because the app server was restarted.
        extIdentityCache.put(oauthDetailsCacheKey, oauthDetails)
        val continueAtOriginalSiteUrl =
          originalSiteOrigin + routes.LoginWithOpenAuthController.continueAtOriginalSite(
            oauthDetailsCacheKey, xsrfToken)
        Redirect(continueAtOriginalSiteUrl)
          .discardingCookies(DiscardingSecureCookie(ReturnToSiteOriginTokenCookieName))
      case None =>
        tryLoginOrShowCreateUserDialog(request, anyOauthDetails = Some(oauthDetails))
    }

    result
  }




  // ======================================================================
  //   Steps after OIDC / OAuth2
  // ======================================================================


  // ------ Login, link accounts, or create new user:


  private def tryLoginOrShowCreateUserDialog(
        request: GetRequest,
        oauthDetailsCacheKey: Opt[St] = None,
        anyOauthDetails: Opt[OpenAuthDetails] = None,
        anyCustomIdp: Opt[IdentityProvider] = None,
        anyReturnToUrl: Opt[St] = None): Result = {

    val dao = request.dao
    val siteSettings = dao.getWholeSiteSettings()

    throwForbiddenIf(siteSettings.enableSso,
          "TyESSO0OAUTHLGI", "OpenAuth login disabled, because SSO enabled")
    throwForbiddenIf(siteSettings.useOnlyCustomIdps && anyCustomIdp.isEmpty,
          "TyECUIDPOAULGI",
          "Default OpenAuth login disabled — using only custom OIDC or OAuth2")

    def cacheKey = oauthDetailsCacheKey.getOrDie("DwE90RW215")
    val oauthDetails: OpenAuthDetails =
      anyOauthDetails.getOrElse(Option(extIdentityCache.getIfPresent(cacheKey)) match {
        case None => throwForbidden("DwE76fE50", "OAuth cache value not found")
        case Some(value) =>
          // Remove to prevent another login with the same key, in case it gets leaked,
          // e.g. via a log file.
          // (Hmm, we remove the OpenAuthDetails entry here, and then add it back again here: (406BM5).
          // Maybe could avoid removing it here. Still, good to do here, so it gets
          // deleted for all code paths below that throws a client error back to the browser.)
          extIdentityCache.invalidate(cacheKey)
          value.asInstanceOf[OpenAuthDetails]
      })

    val loginAttempt = OpenAuthLoginAttempt(
      ip = request.ip, date = globals.now().toJavaDate, oauthDetails)

    val mayCreateNewUserCookie = request.cookies.get(MayCreateUserCookieName)
    val mayCreateNewUser = !mayCreateNewUserCookie.map(_.value).contains("false")

    // COULD let tryLogin() return a LoginResult and use pattern matching, not exceptions.
    //var showsCreateUserDialog = false

    val result = dao.tryLoginAsMember(loginAttempt) match {
      case Good(loginGrant) =>
        createCookiesAndFinishLogin(request, dao.siteId, loginGrant.user,
              anyReturnToUrl = anyReturnToUrl)
      case Bad(problem) =>
        // For now. Later, anyException will disappear.
        if (problem.anyException.isEmpty) {
          // This currently "cannot" happen. [6036KEJ5]
          throwInternalError(
            "TyEUNEXEXC", s"Error logging in: ${problem.message}")
        }
        else problem.anyException.get match {
        // (Fix indentation below later.)
        case DbDao.IdentityNotFoundException =>
          // Let's check if the user already exists, and if so, create an OpenAuth identity
          // and connect it to the user.
          // Details: The user might exist, although no identity was found, if the user
          // has already 1) signed up as an email + password user, or 2) accepted an invitation
          // (when the user clicks the invitation link in the invite email, a user entry
          // is created automatically, without the user having to login). Or 3) signed up
          // via e.g. a Twitter account and specified a Google email address like
          // user@whatever.com (but not gmail.com) and then later attempts to log in
          // via this Google email address instead of via Twitter.
          // Or perhaps 4) signed up via a Facebook account that uses a Google address
          // like user@whatever.com (but not gmail.com).

          // Save canonical email? [canonical-email]

          // (Could ask if the user wants to continue using the email
          // address and preferred username etc, from the IDP.
          // Or if hen wants to, say, use a different email address.
          // But no one has asked about this, so skip for now.)

          // Maybe first verify any email addr provided by the IDP?  [email_privacy]
          // So cannot figure out if there's already another account
          // with the same email — unless it's one's own email.
          // Currently one has to use the email from the IDP anyway,
          // if it's been verified by the IDP.  [use_idp_email]


          /* remove comment:
          PRIVACY; COULD // verify email directly, always,   DOING NOW ALREADY
          // instead of only if
          // there's already an old account with the same email (and otherwise,
          // later, in the create account dialog).
          // So won't reveal that there is an existing account with the same
          // email. However then need to allow trying to create an account,
          // with an email address that is already in use, always when signing up.
          // However! If migrating from email+password login, to OIDC,
          // then, it'd be annoying if everyone has to start creating new
          // accounts, when they login via OIDC the first time.
          // So, maybe sometimes one want to try to auto-link first,
          // rather than starting a create-account process.
          // [many_emails] [email_privacy]
           */

          oauthDetails.email.flatMap(dao.loadMemberByEmailOrUsername) match {
            case Some(user) =>
              if (oauthDetails.isEmailVerifiedByIdp isNot true) {
                sendEmailVerifEmailThenMaybeLinkToUser(oauthDetails, user, request)
              }
              else {
                askIfLinkAccounts(oauthDetails, user, request)
              }

              /*
              // Note that the old account also needs to have verified
              // the email address! Otherwise someone, Mallory, could sign up with
              // another person's, Vic's, email address, not verify it
              // (couldn't — not his addr) and then, when Vic later signs up,
              // Vic's IDP identity would get linked to Mallory's old account
              // — and Mallory could thereafter login as Vic!
              // That'd be an "Account fixation attack"? [act_fx_atk]
              // Reminds of session fixation.
              //
              val identityEmailVerified = providerHasVerifiedEmail(oauthDetails)
              if (identityEmailVerified && user.emailVerified) {
                // UX: Maybe ask if wants to link? See  askIfLinkAccounts()  below.
                // Not impossible the user instead wants to link to *another*
                // account hen might have here, and not use the email from the IDP
                // this time. But would be very rare — who wants more than one
                // account anyway!
                val identity = dao.createIdentityLinkToUser(user, oauthDetails)
                val loginGrant = MemberLoginGrant(
                      Some(identity), user, isNewIdentity = true, isNewMember = false)
                createCookiesAndFinishLogin(request, dao.siteId, loginGrant.user)
              }
              else if (!user.emailVerified && identityEmailVerified) {
                // Then what?
                // Ask the one who logged in, if the old account is really
                // hens account?
                // Thereafter, ask if wants to link them?
              }
              else {
                // Ask the user if hen wants to link this OAuth identity with
                // the old account with the same email.
                // If yes, then, we'll send a verification email, since we don't
                // know if it's really the user's address.
                askIfLinkAccounts(oauthDetails, oauthEmailVerified = false,
                      connectWith = user, customIdp)

                /* OLD: (did C below)
                // There is no reliable way of knowing that the current user is really
                // the same one as the old user in the database? We don't know if the
                // OpenAuth provider has verified the email address.
                // What we can do, is to:
                // A) instruct the user to 1) login as the user in the database
                // (say, via Twitter, in case 3 above). And then 2) click
                // an Add-OpenAuth/OpenID-account button, and then login again in the
                // way s/he attempted to do right now. Then, since the user is logged
                // in at both providers (e.g. both Twitter and Google, in case 3 above)
                // we can safely connect this new OpenAuth identity to the user account
                // already in the database. This is how StackOverflow does it.
                //  See: http://stackoverflow.com/questions/6487418/
                //                  how-to-handle-multiple-openids-for-the-same-user
                // Or B) Perhaps we can ask the user to login as the Twitter user directly?
                // From here, when already logged in with the oauthDetails.
                // (Instead of first logging in via Google then Twitter).
                // Or C) Or we could just send an email address verification email?
                // But then we'd reveal the existence of the Twitter account. And what if
                // the user clicks the confirmation link in the email account without really
                // understanding what s/he is doing? I think A) is safer.
                // Anyway, for now, simply:
                // (Use "user" for the provider's account, and "account" for the account in
                // this server)
                val emailAddress = oauthDetails.email.getOrDie("EsE2FPK8")
                throwForbidden("DwE7KGE32", "\n"+o"""You already have an account with email address
                  $emailAddress, and your ${oauthDetails.providerId} user has the same
                  email address. Since you already have an account here, please don't login via
                  ${oauthDetails.providerId} —
                  instead login using your original login method, e.g. ${
                    someProvidersExcept(oauthDetails.providerId)},
                  or username and password. — I hope you remember which one.""" +
                  "\n\n" +
                  o"""The reason I do not currently let you login via the
                  ${oauthDetails.providerId} user with email $emailAddress
                  is that I don't know if ${oauthDetails.providerId}
                  has verified that the email address is really yours — because if it is not,
                  then you would get access to someone else's account, if I did let you login.""" +
                  "\n\n")
                // If the user does *not* own the email address, s/he would be able to
                // impersonate another user, when his/her new account gets associated with
                // the old one just because they both claim to use the same email address.
                */
              }
              */

            case None =>
              // Create new account?

              throwForbiddenIf(!siteSettings.allowSignup,
                  "TyE0SIGNUP02A", "Creation of new accounts is disabled")

              // Better let IDPs check email domains themselves, if they want to?
              // Dupl check [305RKTG2]
              throwForbiddenIf(!oauthDetails.isSiteCustomIdp &&
                    !siteSettings.isEmailAddressAllowed(
                        oauthDetails.emailLowercasedOrEmpty),
                    "TyEBADEMLDMN_-OAUTH_", "You cannot sign up with that email address")

              // COULD show a nice error dialog instead.
              throwForbiddenIf(!mayCreateNewUser, "DwE5FK9R2",
                    o"""Access denied. You don't have an account
                    at this site with ${oauthDetails.serverDefaultIdpId} login. And you may not
                    create a new account to access this resource.""")

              //showsCreateUserDialog = true
              showCreateUserDialog(request, oauthDetails)
          }
        case ex: QuickMessageException =>
          logger.warn(s"Deprecated exception [TyEQMSGEX03]", ex)
          throwForbidden("TyEQMSGEX03", ex.getMessage)
        case ex: Exception =>
          logger.error(s"Unexpected exception [TyEQMSGEX04]", ex)
          throwInternalError("TyEQMSGEX03", ex.getMessage)
        }
    }

    // COULD avoid deleting cookies if we have now logged in (which we haven't, if
    // the create-user dialog is shown: showsCreateUserDialog == true). Otherwise,
    // accidentally reloading the page, results in weird errors, like the xsrf token
    // missing. But supporting page reload here requires fairly many mini fixes,
    // and maybe is marginally worse for security? since then someone else,
    // e.g. an "evil" tech support person, can ask for and reuse the url?
    result.discardingCookies(CookiesToDiscardAfterLogin: _*)
  }

  /*
  private def someProvidersExcept(providerId: String) =
    Seq(GoogleProvider.ID, FacebookProvider.ID, TwitterProvider.ID, GitHubProvider.ID,
      LinkedInProvider.ID)
      .filterNot(_ equalsIgnoreCase providerId).mkString(", ")
  */



  // ------ Login directly


  private def createCookiesAndFinishLogin(
        request: DebikiRequest[_], siteId: SiteId, member: User,
        anyReturnToUrl: Opt[St] = None): Result = {

    request.dao.pubSub.userIsActive(request.siteId, member, request.theBrowserIdData)
    val (sid, _, sidAndXsrfCookies) = createSessionIdAndXsrfToken(siteId, member.id)

    var maybeCannotUseCookies =
      request.headers.get(EdSecurity.AvoidCookiesHeaderName) is EdSecurity.Avoid

    def weakSessionIdOrEmpty =
      if (maybeCannotUseCookies)
        sid.value
      else
        ""

    val response =
      if (isAjax(request.underlying)) {
        // We've shown but closed an OAuth provider login popup, and now we're
        // handling a create-user Ajax request from a certain showCreateUserDialog()
        // Javascript dialog. It already knows about any pending redirects.
        OkSafeJson(Json.obj(
          "userCreatedAndLoggedIn" -> JsTrue,
          "emailVerifiedAndLoggedIn" -> JsBoolean(member.emailVerifiedAt.isDefined),
          // In case we're in a login popup for [an embedded <iframe> with cookies disabled],
          // send the session id in the response body, so the <iframe> can access it
          // and remember it for the current page load.
          "weakSessionId" -> JsString(weakSessionIdOrEmpty))) // [NOCOOKIES]
      }
      else {
        // In case we need to do a cookieless login:
        // This request is a redirect from e.g. Gmail or Facebook login, so there's no
        // AvoidCookiesHeaderName header that tells us if we are in an iframe and maybe cannot
        // use cookies (because of e.g. Safari's "Intelligent Tracking Prevention").
        // However, we've remembered already, in a 1st party cookie (in the login popup?),
        // if 3rd party iframe cookies not work.
        maybeCannotUseCookies ||=
          request.cookies.get(AvoidCookiesCookieName).map(_.value) is EdSecurity.Avoid

        val isInLoginPopup = request.cookies.get(IsInLoginPopupCookieName).nonEmpty
        def loginPopupCallback: Result =
          Ok(views.html.login.loginPopupCallback(
            weakSessionId = weakSessionIdOrEmpty).body) as HTML // [NOCOOKIES]

        anyReturnToUrl.orElse(request.cookies.get(
                ReturnToUrlCookieName).map(_.value)) match {  // [49R6BRD2]
          case Some(returnToUrl) =>
            if (returnToUrl.startsWith(
                LoginWithPasswordController.RedirectFromVerificationEmailOnly)) {
              // We are to redirect only from new account email address verification
              // emails, not from here.
              loginPopupCallback
            }
            else if (isInLoginPopup) {
              // Javascript in the popup will call handleLoginResponse() which calls
              // continueAfterLogin().
              loginPopupCallback
            }
            else {
              // Currently only happens in the create site wizard (right?), and this redirects to
              // the next step in the wizard.
              Redirect(returnToUrl)
            }
          case None =>
            // If we're in a login window, there's no window.opener, so
            // window.opener.debiki.internal.handleLoginResponse(..)
            //  would fail, here: [login_cont_in_opnr].
            bugWarnIf(!isInLoginPopup, "TyEWINOPNR5",
                  s"s$siteId: Was in login win, but no return-to-url: $member")

            // We're logging in an existing user in a popup window.
            loginPopupCallback
        }
      }

    response.withCookies(sidAndXsrfCookies: _*)
  }



  // ------ Link accounts


  private def sendEmailVerifEmailThenMaybeLinkToUser(oauthDetails: OpenAuthDetails,
          user: User, request: GetRequest): Result = {
    import request.{dao, siteId}

    val emailToVerify = oauthDetails.email.getOrDie(
        "TyE40BKSRT53", s"s$siteId: No email: $oauthDetails")

    // But what about secondary addresses?
    dieIf(emailToVerify != user.primaryEmailAddress, "TyE39TKRSTRS20")

    val expMins = MaxEmailSecretLinkAgeMinutes
    val verifSecret = nextRandomString()
    linkAccountsCache.put(verifSecret, (oauthDetails, user))

    COULD // use Redis instead
    //dao.redisCache.saveOneTimeSecretKeyVal(
    //      emailVerifSecret,  ...serialize-to-json..., expSecs = expMins * 60)

    val subject = s"[${dao.theSiteName()}] Verify your email address" // prettify
    val emailVerifUrl =
          originOf(request) +
          controllers.routes.LoginWithOpenAuthController.verifEmailAskIfLinkAccounts(
              verifSecret = verifSecret).url
    val email = Email(
          EmailType.LinkAccounts,
          createdAt = globals.now(),
          sendTo = user.primaryEmailAddress,
          toUserId = Some(user.id),
          subject = subject,
          bodyHtmlText = (emailId: String) => {
            i"""
              |<tt>
              |  $emailVerifUrl
              |</tt>
              |""" /*
            views.html.resetpassword.resetPasswordEmail(
              userName = user.theUsername,
              emailId = emailId,
              siteAddress = request.host,
              expiresInMinutes = ed.server.MaxResetPasswordEmailAgeMinutes,
              globals = globals).body */
          })
    dao.saveUnsentEmail(email)
    globals.sendEmail(email, dao.siteId)

    Ok(i"""
          |Verify your email address:
          |
          |We sent you an email, title:  $subject
          |
          |So, check your email inbox:  $emailToVerify
          |
          |You can close this page.
          |The link in the email expires in $expMins minutes.
          |""") as TEXT    // I18N
  }


  def verifEmailAskIfLinkAccounts(verifSecret: St): Action[U] =
          GetActionAllowAnyoneRateLimited(RateLimits.LinkExtIdentity) { request =>
    val (identity: OpenAuthDetails, user: User) =
            Option(linkAccountsCache.getIfPresent(verifSecret))
              .getOrThrowForbidden("TyEVERFEMLLNACCTS", s"Bad or expired verifSecret")
    // Don't reuse secrets.
    linkAccountsCache.invalidate(verifSecret)
    askIfLinkAccounts(identity, user, request)
  }


  def askIfLinkAccounts(identity: OpenAuthDetails, user: User, request: ApiRequest[_])
          : Result = {
    import request.dao
    val userInclDetails = dao.loadTheUserInclDetailsById(user.id)
    val idpName = dao.getIdentityProviderNameFor(identity)
          .getOrThrowForbidden("TyEIDPGONE3905", "Identity provider was just deleted?")
    val linkSecret = nextRandomString()
    linkAccountsCache.put(linkSecret, (identity, user))
    Ok(views.html.login.askIfLinkAccounts(
          tpi = SiteTpi(request),
          oldEmailAddr = user.primaryEmailAddress,
          oldEmailVerified = user.emailVerified,
          oldUsername = user.theUsername,
          createdOnDate = toIso8601Day(userInclDetails.createdAt.toJavaDate),
          newIdentityName = identity.nameOrUsername getOrElse identity.email.get,
          idpName = idpName,
          linkSecret = linkSecret))
  }


  /*
  private def askIfLinkAccounts(oauthDetails: OpenAuthDetails,
        oauthEmailVerified: Bo, connectWith: User, customIdp: Opt[IdentityProvider])
        : Result = {
    unimplIf(oauthEmailVerified, "TyE35KSSK2MS")
    val linkAccountsCacheSecret = nextRandomString()
    linkAccountsCache.put(linkAccountsCacheSecret, (oauthDetails, connectWith))
    Ok(views.html.login.askIfLinkAccounts(
          oldEmailAddr = connectWith.primaryEmailAddress,
          newIdentityName = oauthDetails.nameOrUsername getOrElse oauthDetails.email.get,
          idpName = customIdp.map(_.nameOrAlias) getOrElse oauthDetails.providerId,
          tryLinkSecret = linkAccountsCacheSecret))
  }


  def sendLinkAccountsVerifEmail(tryLinkSecret: St): Action[Unit] =
          GetActionAllowAnyoneRateLimited(RateLimits.LinkExtIdentity) {
              request =>
    import request.{dao, siteId}

    val (oauthDetails, user) =
          Option(linkAccountsCache.getIfPresent(tryLinkSecret))
            .getOrThrowBadRequest("TyETRYLNACTSEC", s"Bad or expired tryLinkSecret")

    // Don't reuse secrets.
    linkAccountsCache.invalidate(tryLinkSecret)

    // Verify user owns the account.
    val emailToVerify = oauthDetails.email.getOrDie(
          "TyE04KSRT53", s"s$siteId: No email: $oauthDetails")

    // But what about secondary addresses?
    dieIf(emailToVerify != user.primaryEmailAddress, "TyE39TKRSTRS20")

    val doLinkSecret = nextRandomString()
    linkAccountsCache.put(doLinkSecret, (oauthDetails, user))

    val email = Email(
      EmailType.LinkAccounts,
      createdAt = globals.now(),
      sendTo = user.primaryEmailAddress,
      toUserId = Some(user.id),
      subject = s"[${dao.theSiteName()}] Link accounts?",
      bodyHtmlText = (emailId: String) => {
        s"<tt>/-/do-link-accounts?doLinkSecret=${doLinkSecret}</tt>" /*
        views.html.resetpassword.resetPasswordEmail(
          userName = user.theUsername,
          emailId = emailId,
          siteAddress = request.host,
          expiresInMinutes = ed.server.MaxResetPasswordEmailAgeMinutes,
          globals = globals).body */
      })
    dao.saveUnsentEmail(email)
    globals.sendEmail(email, dao.siteId)

    Ok(s"\n\nCheck your email, that is: $emailToVerify" +
        "\n\n\nYou can close this page.\n\n") as TEXT    // I18N
  }  */


  def answerLinkAccounts: Action[JsonOrFormDataBody] = JsonOrFormDataPostAction(
        RateLimits.LinkExtIdentity, maxBytes = 200, allowAnyone = true,
        skipXsrfCheck = true, // the linkSecret input is enough
        ) { request =>
    import request.dao

    val choiceStr = request.body.getOrThrowBadReq("choice")
    val shallLink = choiceStr match {
      case "YesLn" => true
      case "NoCancel" => false
      case bad => throwBadParam("TyE305RKFDJ3", "choice", bad)
    }

    val linkSecret = request.body.getOrThrowBadReq("linkSecret")
    val (oauthDetails, user) =
          Option(linkAccountsCache.getIfPresent(linkSecret))
            .getOrThrowBadRequest("TyEDOLNACTSEC", s"Bad or expired linkSecret")
    linkAccountsCache.invalidate(linkSecret)

    if (!shallLink) {
      // Then what? Create new account with same email? Unimplemented.
      // For now:  (note that this current user controls the email addr of
      // that other account — so gets to decide what to do with it)
      Ok("\nOk.\n\nMaybe you'd like to ask the site admins if " +
          "they can delete that other account?\n\n") as TEXT
    }
    else {
    /*
  def doLinkAccounts(doLinkSecret: St): Action[Unit] =
          GetActionAllowAnyoneRateLimited(RateLimits.ResetPassword) {  // or what limits?
            request =>
    import request.dao

    val (oauthDetails, user) =
          Option(linkAccountsCache.getIfPresent(doLinkSecret))
            .getOrThrowBadRequest("TyEDOLNACTSEC", s"Bad or expired doLinkSecret")

    linkAccountsCache.invalidate(doLinkSecret)
    */

    // Don't login — it's better to ask hen to try again, so hen will notice
    // immediately if won't work, rather than some time later, when hen
    // has forgotten that hen (tried to) link the accounts, and cannot provide
    // the support staff with any meaningful info other than "it not work"?
    dao.createIdentityLinkToUser(user, oauthDetails)

    Ok("\nDone.\n\n\nCan you please try to login again?\n\n") as TEXT  // prettify
  }}



  // ------ Create new user


  private def showCreateUserDialog(request: GetRequest, oauthDetails: OpenAuthDetails)
          : Result = {
    import request.dao
    val idpName = dao.getIdentityProviderNameFor(oauthDetails)
          .getOrThrowForbidden("TyEIDPGONE3907", "Identity provider just deleted?")

    // Re-insert the  OpenAuthDetails, we just removed it (406BM5). A bit double work?
    val cacheKey = nextRandomString()
    extIdentityCache.put(cacheKey, oauthDetails)

    val anyIsInLoginWindowCookieValue = request.cookies.get(IsInLoginWindowCookieName).map(_.value)
    val anyReturnToUrlCookieValue = request.cookies.get(ReturnToUrlCookieName).map(_.value)

    val result = if (anyIsInLoginWindowCookieValue.isDefined) {
      // Continue running in the login window, by returning a complete HTML page that
      // shows a create-user dialog. (( This happens if 1) we're in a create
      // site wizard, then there's a dedicated login step in a login window, or 2)
      // we're logging in to the admin pages, or 3) when logging in to a login required site,
      // or 4) we're visiting an embedded comments
      // site and attempted to login, then a login popup window opens (better than
      // showing a login dialog somewhere inside the iframe). ))
      Ok(views.html.login.showCreateUserDialog(
        SiteTpi(request),
        idpName = idpName,
        idpHasVerifiedEmail = oauthDetails.isEmailVerifiedByIdp.is(true),
        serverAddress = s"//${request.host}",
        newUserUsername = oauthDetails.username getOrElse "",
        newUserFullName = oauthDetails.displayNameOrEmpty,
        newUserEmail = oauthDetails.emailLowercasedOrEmpty,
        authDataCacheKey = cacheKey,
        anyContinueToUrl = anyReturnToUrlCookieValue))
    }
    else {
      // The request is from an OAuth provider login popup. Run some Javascript in the
      // popup that continues execution in the main window (the popup's window.opener)
      // and closes the popup.  [2ABKW24T]
      Ok(views.html.login.closePopupShowCreateUserDialog(
        idpName = idpName,
        idpHasVerifiedEmail = oauthDetails.isEmailVerifiedByIdp.is(true),
        newUserUsername = oauthDetails.username getOrElse "",
        newUserFullName = oauthDetails.displayNameOrEmpty,
        newUserEmail = oauthDetails.emailLowercasedOrEmpty,
        authDataCacheKey = cacheKey,
        anyContinueToUrl = anyReturnToUrlCookieValue))
    }

    result.discardingCookies(
      DiscardingSecureCookie(IsInLoginWindowCookieName),
      DiscardingSecureCookie(ReturnToUrlCookieName))
  }


  def handleCreateUserDialog: Action[JsValue] = AsyncPostJsonAction(
        RateLimits.CreateUser, maxBytes = 1000,
        // Could set isLogin = true instead, see handleCreateUserDialog(..) in
        // LoginWithPasswordController, + login-dialog.ts [5PY8FD2]
        allowAnyone = true) { request: JsonPostRequest =>

    // A bit dupl code. [2FKD05]
    import request.{body, dao}

    val siteSettings = dao.getWholeSiteSettings()

    throwForbiddenIf(siteSettings.enableSso,
      "TyESSO0OAUTHNWUSR", "OpenAuth user creation disabled, because SSO enabled")
    // ... But `useOnlyCustomIdps` is fine — here's where we log in
    // via custom IDPs.
    throwForbiddenIf(!siteSettings.allowSignup,
      "TyE0SIGNUP04", "OpenAuth user creation disabled, because new signups not allowed")

    val fullName = (body \ "fullName").asOptStringNoneIfBlank
    val emailAddress = (body \ "email").as[String].trim
    val username = (body \ "username").as[String].trim
    val anyReturnToUrl = (body \ "returnToUrl").asOpt[String]

    val oauthDetailsCacheKey = (body \ "authDataCacheKey").asOpt[String]
          .getOrThrowBadRequest("TyE08GM6", "Auth data cache key missing")
    val oauthDetails = Option(extIdentityCache.getIfPresent(oauthDetailsCacheKey)) match {
      case Some(details: OpenAuthDetails) =>
        // Don't remove the cache key here — maybe the user specified a username that's
        // in use already. Then hen needs to be able to submit again (using the same key).
        details
      case None =>
        throwForbidden("DwE50VC4", o"""Bad auth data cache key — this happens if you wait
             rather long (many minutes) with submitting the dialog.
             Or if the server was just restarted. Please try to sign up again.""")
      case _ =>
        die("TyE2GVM0")
    }

    val emailVerifiedAt = oauthDetails.email flatMap { emailFromIdp =>
      // [use_idp_email]
      throwForbiddenIf(emailFromIdp.toLowerCase != emailAddress, "TyE523FU2",
            o"""When signing up, currently you cannot change your email address
            from the one you use at ${oauthDetails.serverDefaultIdpId}, namely: ${
            oauthDetails.email}""")

        if (oauthDetails.isEmailVerifiedByIdp is true) {
          Some(request.ctime)
        }
        else if (oauthDetails.isEmailVerifiedByIdp is true) {
          // However we don't know how long ago the IDP verified the email.
          Some(request.ctime)
        }
        else {
          None
        }
    }

    // Dupl check [305RKTG2]
    throwForbiddenIf(oauthDetails.isEmailVerifiedByIdp.isNot(true) &&
          !siteSettings.isEmailAddressAllowed(emailAddress),
          "TyEBADEMLDMN_-OAUTHB", "You cannot sign up using that email address")

    // More dupl code. [2FKD05]

    if (!siteSettings.requireVerifiedEmail && emailAddress.isEmpty) {
      // Fine.
    }
    else if (emailAddress.isEmpty) {
      throwUnprocessableEntity("EdE8JUK02", "Email address missing")
    }
    else {
      anyEmailAddressError(emailAddress) foreach { errMsg =>
        throwUnprocessableEntity("TyEBADEMLADR_-OAU", s"Bad email address: $errMsg")
      }
    }

    if (ed.server.security.ReservedNames.isUsernameReserved(username)) // [5LKKWA10]
      throwForbidden("EdE4SWWB9", s"Username is reserved: '$username'; choose another username")

    val spamCheckTask = SpamCheckTask(
      createdAt = globals.now(),
      siteId = request.siteId,
      postToSpamCheck = None,
      who = request.whoOrUnknown,
      requestStuff = request.spamRelatedStuff.copy(
        userName = Some((username + " " + fullName.getOrElse("")).trim),
        userEmail = Some(emailAddress),
        userTrustLevel = Some(TrustLevel.NewMember)))

    globals.spamChecker.detectRegistrationSpam(spamCheckTask) map {
          spamCheckResults: SpamCheckResults =>
      SpamChecker.throwForbiddenIfSpam(spamCheckResults, "TyE2AKF067")

      val becomeOwner = LoginController.shallBecomeOwner(request, emailAddress)

      val userData = // [5LKKWA10]
        NewOauthUserData.create(name = fullName, username = username, email = emailAddress,
            emailVerifiedAt = emailVerifiedAt, identityData = oauthDetails,
            isAdmin = becomeOwner, isOwner = becomeOwner) match {
          case Good(data) => data
          case Bad(errorMessage) =>
            throwUnprocessableEntity("DwE7BD08", s"$errorMessage, please try again.")
        }

      val result = try {
        val loginGrant = dao.createIdentityUserAndLogin(userData, request.theBrowserIdData)
        val newMember = loginGrant.user
        dieIf(newMember.emailVerifiedAt != emailVerifiedAt, "EdE2WEP03")
        if (emailAddress.nonEmpty && emailVerifiedAt.isEmpty) {
          TESTS_MISSING // no e2e tests for this
          val email = LoginWithPasswordController.createEmailAddrVerifEmailLogDontSend(
              newMember, anyReturnToUrl, request.host, request.dao)
          globals.sendEmail(email, dao.siteId)
        }
        if (emailVerifiedAt.isDefined || siteSettings.mayPostBeforeEmailVerified) {
          createCookiesAndFinishLogin(request, request.siteId, loginGrant.user)
        }
        else {
          OkSafeJson(Json.obj(
            "userCreatedAndLoggedIn" -> JsFalse,
            "emailVerifiedAndLoggedIn" -> JsFalse))
        }
      }
      catch {
        case _: DbDao.DuplicateUsername =>
          throwForbidden(
              "DwE6D3G8", "Username already taken, please try again with another username")
        case _: DbDao.DuplicateUserEmail =>
          // BUG SHOULD support many users per email address, if mayPostBeforeEmailVerified.
          if (emailVerifiedAt.isDefined) {
            // The user has been authenticated, so it's okay to tell him/her about the email address.
            throwForbidden(
              "DwE4BME8", "You already have an account with that email address")
          }
          // Don't indicate that there is already an account with this email.
          LoginWithPasswordController.sendYouAlreadyHaveAnAccountWithThatAddressEmail(
            request.dao, emailAddress, siteHostname = request.host, siteId = request.siteId)
          OkSafeJson(Json.obj(
            "userCreatedAndLoggedIn" -> JsFalse,
            "emailVerifiedAndLoggedIn" -> JsFalse))
      }

      // Everything went fine. Won't need to submit the dialog again, so remove the cache key.
      extIdentityCache.invalidate(oauthDetailsCacheKey)

      result.discardingCookies(CookiesToDiscardAfterLogin: _*)
    }
  }



  // ------ Login via Login Origin


  /** Redirects to and logs in via anyLoginOrigin; then redirects back to this site, with
    * a session id and xsrf token included in the GET request.
    */
  private def loginViaLoginOrigin(providerName: String, request: RequestHeader)
        : Future[Result] = {
    // Parallel logins? Is the same user logging in in two browser tabs, at the same time?
    // People sometimes do, for some reason, and if that won't work, they sometimes contact
    // the Talkyard developers and ask what's wrong. Only to avoid these support requests,
    // let's make parallel login work, by including xsrf tokens from all such ongoing logins,
    // in the cookie value. [PRLGIN]
    val anyCookie = request.cookies.get(ReturnToThisSiteXsrfTokenCookieName)
    val oldTokens: Option[String] = anyCookie.map(_.value)

    val newXsrfToken = nextRandomString()
    val newCookieValue = newXsrfToken + Separator + oldTokens.getOrElse("")
    val loginEndpoint =
      globals.anyLoginOrigin.getOrDie("TyE830bF1") +
        routes.LoginWithOpenAuthController.loginAtLoginOriginThenReturnToOriginalSite(
          providerName, returnToOrigin = originOf(request), newXsrfToken)
    Future.successful(Redirect(loginEndpoint).withCookies(
      SecureCookie(name = ReturnToThisSiteXsrfTokenCookieName, value = newCookieValue,
        maxAgeSeconds = Some(LoginTimeoutMins * 60), httpOnly = false)))
  }


  /** Logs in, then redirects back to returnToOrigin, and specifies xsrfToken to prevent
    * XSRF attacks and session fixation attacks.
    *
    * The request origin must be the anyLoginOrigin, because that's the origin that the
    * OAuth 1 and 2 providers supposedly have been configured to use.
    */
  def loginAtLoginOriginThenReturnToOriginalSite(providerName: String,
          returnToOrigin: String, xsrfToken: String): Action[Unit] =
        AsyncGetActionIsLogin { request =>

    // The actual redirection back to the returnToOrigin happens in handleAuthenticationData()
    // — it checks the value of the return-to-origin cookie.
    if (globals.anyLoginOrigin isNot originOf(request))
      throwForbidden(
        "DwE50U2", s"You need to login via the login origin, which is: `${globals.anyLoginOrigin}'")

    val futureResponse = startOrFinishAuthenticationWithSilhouette(providerName, request)
    futureResponse map { response =>
      response.withCookies(
        SecureCookie(name = ReturnToSiteOriginTokenCookieName, value = s"$returnToOrigin$Separator$xsrfToken",
          httpOnly = false))
    }
  }


  def continueAtOriginalSite(oauthDetailsCacheKey: String, xsrfToken: String): Action[Unit] =
        GetActionIsLogin { request =>
    // oauthDetailsCacheKey might be a chache key Mallory generated, when starting a login
    // flow on his laptop — and now he might have made the current requester click a link
    // with that cache key, in the url. So, we also check an xsrf token here.
    val anyXsrfTokenInSession = request.cookies.get(ReturnToThisSiteXsrfTokenCookieName)
    anyXsrfTokenInSession match {
      case Some(xsrfCookie) =>
        // There might be many tokens, if, surprisingly, the user clicks Login in different
        // browser tabs in parallel. [PRLGIN]  ... Oh this doesn't work anyway, because
        // Silhouette stores and overwrites a Silhouette xsrf token in a single cookie.
        // Keep this anyway — maybe Silhouette fixes that issue, and then this Talkyard code here
        // already works properly.
        val tokens = xsrfCookie.value.split(Separator)
        val okToken = tokens.contains(xsrfToken)
        throwForbiddenIf(!okToken,
          "TyEOAUXSRFTKN", o"""Bad XSRF token, not included in the
              $ReturnToThisSiteXsrfTokenCookieName cookie""")
      case None =>
        throwForbidden("TyE0OAUXSRFCO", s"No $ReturnToThisSiteXsrfTokenCookieName xsrf cookie",
            o"""You need to login over at Google or Facebook, within $LoginTimeoutMins minutes,
            once you've started logging in / signing up. Feel free to try again.""")
    }
    tryLoginOrShowCreateUserDialog(request, oauthDetailsCacheKey = Some(oauthDetailsCacheKey))
      .discardingCookies(DiscardingSecureCookie(ReturnToThisSiteXsrfTokenCookieName))
  }


  private val HttpLayer =
    new silhouette.api.util.PlayHTTPLayer(globals.wsClient)(globals.executionContext)

  private val authStuffSigner = new silhouette.crypto.JcaSigner(
    silhouette.crypto.JcaSignerSettings(
      key = globals.applicationSecret, pepper = "sil-pepper-kfw93KPUF02wF"))

  private val Crypter = new silhouette.crypto.JcaCrypter(
    silhouette.crypto.JcaCrypterSettings(key = globals.applicationSecret))

  private def csrfStateItemHandler = new silhouette.impl.providers.state.CsrfStateItemHandler(
    silhouette.impl.providers.state.CsrfStateSettings(
      cookieName = AuthStateCookieName, cookiePath = "/", cookieDomain = None,
      secureCookie = globals.secure, httpOnlyCookie = true, expirationTime = 5 minutes),
    new silhouette.impl.util.SecureRandomIDGenerator(),
    authStuffSigner)

  private val socialStateHandler =
    new silhouette.impl.providers.DefaultSocialStateHandler(
      Set(csrfStateItemHandler), authStuffSigner)

  private val OAuth1TokenSecretProvider =
    new silhouette.impl.providers.oauth1.secrets.CookieSecretProvider(
      silhouette.impl.providers.oauth1.secrets.CookieSecretSettings(
        cookieName = "dwCoOAuth1TokenSecret", secureCookie = globals.secure),
      authStuffSigner,
      Crypter,
      silhouette.api.util.Clock())


  private def googleProvider(): GoogleProvider with CommonSocialProfileBuilder =
    new GoogleProvider(HttpLayer, socialStateHandler,
      getOrThrowDisabled(globals.socialLogin.googleOAuthSettings))

  private def facebookProvider(): FacebookProvider with CommonSocialProfileBuilder =
    new FacebookProvider(HttpLayer, socialStateHandler,
      getOrThrowDisabled(globals.socialLogin.facebookOAuthSettings))

  private def twitterProvider(): TwitterProvider with CommonSocialProfileBuilder = {
    val settings = getOrThrowDisabled(globals.socialLogin.twitterOAuthSettings)
    new TwitterProvider(
      HttpLayer, new PlayOAuth1Service(settings), OAuth1TokenSecretProvider, settings)
  }

  private def githubProvider(): CustomGitHubProvider =   // (TYSOCPROF)
    new CustomGitHubProvider(HttpLayer, socialStateHandler,
      getOrThrowDisabled(globals.socialLogin.githubOAuthSettings),
      globals.wsClient)

  private def gitlabProvider(): GitLabProvider with CommonSocialProfileBuilder =
    new GitLabProvider(HttpLayer, socialStateHandler,
      getOrThrowDisabled(globals.socialLogin.gitlabOAuthSettings))

  private def linkedinProvider(): CustomLinkedInProvider with CommonSocialProfileBuilder =
    new CustomLinkedInProvider(HttpLayer, socialStateHandler,
      getOrThrowDisabled(globals.socialLogin.linkedInOAuthSettings),
      globals.wsClient)

  private def vkProvider(): VKProvider with CommonSocialProfileBuilder =
    new VKProvider(HttpLayer, socialStateHandler,
      getOrThrowDisabled(globals.socialLogin.vkOAuthSettings))

  private def instagramProvider(): InstagramProvider with CommonSocialProfileBuilder =
    new InstagramProvider(HttpLayer, socialStateHandler,
      getOrThrowDisabled(globals.socialLogin.instagramOAuthSettings))


  private def getOrThrowDisabled[A](anySettings: A Or ErrorMessage): A = anySettings match {
    case Good(settings) => settings
    case Bad(errorMessage) => throwForbidden("EsE5YFK02", errorMessage)
  }

}



case class ExternalEmailAddr(
  emailAddr: String,
  isPrimary: Boolean,
  isVerified: Boolean,
  isPublic: Boolean)


sealed abstract class Gender
object Gender {
  case object Male extends Gender
  case object Female extends Gender
  case object Other extends Gender
}


case class ExternalSocialProfile(   // RENAME to ExternalIdentity? It's from an Identity Provider (IDP)
  providerId: String,
  providerUserId: String,
  username: Option[String],
  firstName: Option[String],
  lastName: Option[String],
  fullName: Option[String],
  gender: Option[Gender],
  avatarUrl: Option[String],
  publicEmail: Option[String],
  publicEmailIsVerified: Option[Boolean],
  primaryEmail: Option[String],
  primaryEmailIsVerified: Option[Boolean],
  company: Option[String],
  location: Option[String],
  aboutUser: Option[String],
  facebookUrl: Option[String] = None,
  githubUrl: Option[String] = None,
  createdAt: Option[String]) extends SocialProfile {

  require(publicEmail.isDefined == publicEmailIsVerified.isDefined, "TyE7KBRAW02")
  require(primaryEmail.isDefined == primaryEmailIsVerified.isDefined, "TyE7KBRAW03")

  def loginInfo = LoginInfo(providerId, providerUserId)

}



class CustomGitHubProfileParser(
  val executionContext: ExecutionContext,
  val wsClient: play.api.libs.ws.WSClient,
  val githubApiBaseUrl: String)
  extends SocialProfileParser[JsValue, ExternalSocialProfile, OAuth2Info]
  with TyLogging {

  import play.api.libs.ws

  /** Parses json from GitHub that describes a user with an account at GitHub.
    * The json docs: https://developer.github.com/v3/users/#response
    */
  def parse(json: JsValue, authInfo: OAuth2Info): Future[ExternalSocialProfile] = {
    val anyEmailsFuture = loadPublicAndVerifiedEmailAddrs(authInfo)
    anyEmailsFuture.map({ case (anyPublAddr, anyPrimAddr) =>
      try {
        // GitHub user Json docs:  https://developer.github.com/v3/users/#response
        ExternalSocialProfile(
          providerId = GitHubProvider.ID,
          providerUserId = (json \ "id").as[Long].toString,
          username = (json \ "login").asOptStringNoneIfBlank,
          firstName = None,
          lastName = None,
          fullName = (json \ "name").asOptStringNoneIfBlank,
          gender = None,
          avatarUrl = (json \ "avatar_url").asOptStringNoneIfBlank,
          publicEmail = anyPublAddr.map(_.emailAddr),
          publicEmailIsVerified = anyPublAddr.map(_.isVerified),
          primaryEmail = anyPrimAddr.map(_.emailAddr),
          primaryEmailIsVerified = anyPrimAddr.map(_.isVerified),
          company = (json \ "company").asOptStringNoneIfBlank,
          location = (json \ "location").asOptStringNoneIfBlank,
          aboutUser = (json \ "bio").asOptStringNoneIfBlank,
          // api url, for loading user json: (json \ "url"), but we
          // want the html profile page url, and that's 'html_url'.
          githubUrl = (json \ "html_url").asOptStringNoneIfBlank,
          createdAt = (json \ "created_at").asOptStringNoneIfBlank)
      }
      catch {
        case ex: Exception =>
          // Add this more detailed exception cause to the exception chain.
          PRIVACY // Someone's email might end up in the log files.
          throw new RuntimeException(
            s"Unexpected user profile json from GitHub: ${json.toString()} [TyE5ARQ2HE7]", ex)
      }
    })(executionContext)
  }


  /** GitHub doesn't include any email, if there's no publicly visibly email configured,
    * and that might not be a verified email? Here we load a verified, and preferably
    * primary, email address.
    */
  private def loadPublicAndVerifiedEmailAddrs(oauth2AuthInfo: OAuth2Info)
        : Future[(Option[ExternalEmailAddr], Option[ExternalEmailAddr])] = {
    // List user email addresses docs:
    //   https://developer.github.com/v3/#oauth2-token-sent-in-a-header
    val url = s"$githubApiBaseUrl/emails"
    val githubRequest: ws.WSRequest =
      wsClient.url(url).withHttpHeaders(
        // Auth docs: https://developer.github.com/v3/#oauth2-token-sent-in-a-header
        // OAuth2 bearer token. GitHub will automatically know which user the request concerns
        // (although not mentioned in the request URL).
        play.api.http.HeaderNames.AUTHORIZATION -> s"token ${oauth2AuthInfo.accessToken}",
        // Use version 3 of the API, it's the most recent one (as of 2019-03).
        // https://developer.github.com/v3/#current-version
        play.api.http.HeaderNames.ACCEPT -> "application/vnd.github.v3+json")

    githubRequest.get().map({ response: ws.WSResponse =>
      // GitHub's response is (as of 2018-10-13) like:
      // https://developer.github.com/v3/users/emails/#list-email-addresses-for-a-user
      // [{ "email": "a@b.c", "verified": true, "primary": true, "visibility": "public" }]
      try {
        val statusCode = response.status
        val bodyAsText = response.body
        if (statusCode != 200) {
          logger.warn(o"""Unexpected status: $statusCode, from GitHub
            when loading email address [TyEGITHUBEMLS], url: $url, response: $bodyAsText""")
          (None, None)
        }
        else {
          val bodyAsJson = Json.parse(bodyAsText)
          val emailObjs: Seq[JsValue] = bodyAsJson.asInstanceOf[JsArray].value
          val emails: Seq[ExternalEmailAddr] = emailObjs.map({ emailObjUntyped: JsValue =>
            val emailObj = emailObjUntyped.asInstanceOf[JsObject]
            ExternalEmailAddr(
              emailAddr = emailObj.value.get("email").map(_.asInstanceOf[JsString].value)
                .getOrDie("TyE5RKBW20P", s"Bad JSON from GitHub: $bodyAsText"),
              isVerified = emailObj.value.get("verified") is JsTrue,
              isPrimary = emailObj.value.get("primary") is JsTrue,
              isPublic = emailObj.value.get("visibility") is JsString("public"))
          })

          val anyPublAddr =
            emails.find(e => e.isPublic && e.isVerified) orElse
              emails.find(_.isPublic)

          val anyPrimaryAddr =  // [7KRBGQ20]
            emails.find(e => e.isPrimary && e.isVerified) orElse
              emails.find(e => e.isPublic && e.isVerified) orElse
              emails.find(_.isVerified)

          (anyPublAddr, anyPrimaryAddr)
        }
      }
      catch {
        case ex: Exception =>
          logger.warn("Error parsing GitHub email addresses JSON [TyE4ABK2LR7]", ex)
          (None, None)
      }
    })(executionContext).recoverWith({
      case ex: Exception =>
        logger.warn("Error asking GitHub for user's email addresses [TyE8BKAS225]", ex)
        Future.successful((None, None))
    })(executionContext)
  }
}


class CustomGitHubProvider(
  protected val httpLayer: HTTPLayer,
  protected val stateHandler: SocialStateHandler,
  val settings: OAuth2Settings,
  wsClient: play.api.libs.ws.WSClient) extends BaseGitHubProvider {
                                        // no: with CommonSocialProfileBuilder {
                                        // — maybe create a TalkyardSocialProfileBuilder?  (TYSOCPROF)
                                        //  or TyExternalSocialProfileBuilder?
                                        // "Ty" prefix = clarifies isn't Silhouette's built-in class.

  // This is the base api url, used to construct requests to the GitHub server.
  val apiBaseUrl: String = apiUserUrl

  private var warnedAboutOldAuth = false

  override protected val urls: Map[String, String] = Map("api" -> apiUserUrl)

  // The url to fetch the user's profile, from the GitHub server.
  // For GitHub.com, it's GitHubProvider.API = "https://api.github.com/user".
  // And for GitHub Enterprise, it's "https://own.github/api/v3/user?access_token=%s".
  // Dropping-right up to and incl the rightmost '/' results in the api base url,
  // which can be used to construct other requests to GitHub.
  def apiUserUrl: String = settings.apiURL.map(url => {
    // From 2020-02-10, Git revision 2c94117d54319c1a, Silhouette no longer wants
    // "?access_token=%s", but instead uses the auth header:
    //     Authorization: Bearer the-access-token
    // However, the Talkyard config might still include the "?access_token=%s" suffix,
    // which would make GitHub reply 400 Bad Request. So:
    var u = url.trim()
    val accessTokenQueryParam = "?access_token=%s"
    if (u.contains(accessTokenQueryParam)) {
      u = u.replaceAllLiterally(accessTokenQueryParam, "")
      if (!warnedAboutOldAuth) {
        warnedAboutOldAuth = true
        logger.warn(o"""Deprecated GitHub auth conf: Remove "$accessTokenQueryParam" from
            the  github.apiURL  config value, in  $ProdConfFilePath.""")
      }
    }
    u
  }).getOrElse(
    com.mohiva.play.silhouette.impl.providers.oauth2.GitHubProvider.API)

  type Self = CustomGitHubProvider

  override type Profile = ExternalSocialProfile

  val profileParser = new CustomGitHubProfileParser(executionContext, wsClient, apiBaseUrl)

  def withSettings(fn: Settings => Settings): CustomGitHubProvider = {
    new CustomGitHubProvider(httpLayer, stateHandler, fn(settings), wsClient)
  }
}



// Silhouette doesn't yet support LinkedIn API v2 so using this class,
// temporarily.
// Also need this OAuth2Settings setting:
// apiURL = Some("https://api.linkedin.com/v2/me?fields=id,firstName,lastName&oauth2_access_token=%s")
class CustomLinkedInProvider(
  protected val httpLayer: HTTPLayer,
  protected val stateHandler: SocialStateHandler,
  val settings: OAuth2Settings,
  wsClient: play.api.libs.ws.WSClient)
  extends BaseLinkedInProvider with CommonSocialProfileBuilder {

  override type Self = CustomLinkedInProvider

  override val profileParser = new LinkedInProfileParserApiV2(executionContext, wsClient)

  override def withSettings(f: (Settings) => Settings) =
    new CustomLinkedInProvider(httpLayer, stateHandler, f(settings), wsClient)
}


class LinkedInProfileParserApiV2(
  val executionContext: ExecutionContext,
  val wsClient: play.api.libs.ws.WSClient)
  extends SocialProfileParser[JsValue, CommonSocialProfile, OAuth2Info]
  with TyLogging {

  override def parse(json: JsValue, authInfo: OAuth2Info): Future[CommonSocialProfile] = {
    // Silhouette now includes the email in the json, so skip loadEmailAddr().
    // loadEmailAddr(authInfo).map({ anyEmail =>

      // See  BaseLinkedInProvider.buildProfile().
      val apiJsonObj   = json \ "api"
      val emailJsonObj = json \ "email"
      val photoJsonObj = json \ "photo"

      val anyEmail = (emailJsonObj \\ "emailAddress").headOption.flatMap(_.asOpt[String])

      // The apiJsonObj from API v2 is like:
      // {
      //   "lastName":{
      //     "localized":{"en_US":"MyLastName"},
      //     "preferredLocale":{"country":"US","language":"en"}},
      //   "firstName":{
      //     "localized":{"en_US":"MyFirstName"},
      //     "preferredLocale":  {"country":"US","language":"en"}},
      //   "id":"........"   // "random" chars
      // }

      // Other fields? No. Here:
      // https://docs.microsoft.com/en-us/linkedin/shared/references/v2/profile#profile-fields-available-with-linkedin-partner-programs
      // you'll see that one needs to "have applied and been approved for a LinkedIn Partner Program",
      // to access more fields.

      val userId = (apiJsonObj \ "id").as[String]
      def readName(fieldName: String): Option[String] = {
        (apiJsonObj \ fieldName).asOpt[JsObject] flatMap { jsObj =>
          (jsObj \ "localized").asOpt[JsObject] flatMap { jsObj =>
            jsObj.fields.headOption.map(_._2) flatMap { nameInAnyLocale =>
              nameInAnyLocale match {
                case jsString: JsString => Some(jsString.value)
                case _ => None
              }
            }
          }
        }
      }
      val firstName = readName("firstName")
      val lastName = readName("lastName")

      val profile = CommonSocialProfile(
        loginInfo = LoginInfo(LinkedInProvider.ID, userId),
        firstName = firstName,
        lastName = lastName,
        fullName = None,    // not incl in LinkedIn API v2
        avatarURL = None,   // not incl in LinkedIn API v2
        email = anyEmail)

    Future.successful(profile)
    //})(executionContext)
  }


  /** LinkedIn API v2 requires a separate request to fetch the email address.
    *
    * Update, 2020-04: Silhouette 7.0 now loads the email in a 2nd request itself.
    * So, disabling this fn for now.
    *
    * But keep it commented in, so can fix complation errors, keep it somewhat
    * up-to-date, maybe needed soon again?
    */
  private def loadEmailAddr(oauth2AuthInfo: OAuth2Info): Future[Option[String]] = {
    die("TyE39572KTSP3", "loadEmailAddr() not needed, don't call")

    import play.api.libs.ws
    val emailRequestUrl =
      "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))" +
      "&oauth2_access_token=" + oauth2AuthInfo.accessToken
    val linkedinRequest: ws.WSRequest = wsClient.url(emailRequestUrl)

    linkedinRequest.get().map({ response: ws.WSResponse =>
      // LinkedIn's response is (as of 2019-04) like:
      // { "elements": [
      //   { "handle": "urn:li:emailAddress:1234567890",
      //      "handle~": { "emailAddress": "someone@example.com"  }} ]}
      try {
        val bodyAsText = response.body
        val bodyAsJson = Json.parse(bodyAsText)
        val elementsJsArray = (bodyAsJson \ "elements").as[JsArray]
        val elemOne = elementsJsArray.value.headOption match {
          case Some(o: JsObject) => o
          case Some(x) => throwUnprocessableEntity("TyEJSN0L245", s"Weird elem class: ${classNameOf(x)}")
          case None => throwUnprocessableEntity("TyEJSN2AKB05", "No email elem")
        }
        val handleObj = (elemOne \ "handle~").as[JsObject]
        val addr = (handleObj \ "emailAddress").as[JsString].value
        Some(addr)
      }
      catch {
        case ex: Exception =>
          logger.warn("Error parsing LinkedIn email address JSON [TyE7UABKT32]", ex)
          None
      }
    })(executionContext).recoverWith({
      case ex: Exception =>
        logger.warn("Error asking LinkedIn for user's email address [TyE5KAW2J]", ex)
        Future.successful(None)
    })(executionContext)
  }
}
