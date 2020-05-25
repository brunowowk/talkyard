package talkyard.server

import com.debiki.core.Prelude.stringToRichString
import com.debiki.core.{ErrMsg, GetOrBadMap, IdentityProvider, OpenAuthDetails}
import debiki.JsonUtils._
import org.scalactic.{Bad, Good, Or}
import play.api.libs.json.JsValue
import talkyard.server.authn.OidcClaims.parseOidcClaims


package object authn {


  def parseOidcUserInfo(jsVal: JsValue, idp: IdentityProvider)
        : OpenAuthDetails Or ErrMsg = {

    val jsObj = asJsObject(jsVal, what = "OIDC user info")

    val claims = parseOidcClaims(jsObj) getOrIfBad { errMsg =>
      return Bad(errMsg)
    }

    val anyName = claims.name
          .orElse(Seq(
              claims.given_name,
              claims.middle_name,
              claims.family_name).flatten.mkString(" ").trimNoneIfEmpty)
          .orElse(claims.nickname)
          .orElse(claims.preferred_username)

    Good(OpenAuthDetails(
          serverDefaultIdpId = None,
          siteCustomIdpId = Some(idp.id_c),
          idpUserId = claims.sub,
          username = claims.preferred_username,
          firstName = claims.given_name,
          lastName = claims.family_name,
          fullName = anyName,
          email = claims.email,
          isEmailVerifiedByIdp = Some(claims.email_verified),
          avatarUrl = claims.picture,
          userInfoJson = Some(jsObj)))
  }


  def parseCustomUserInfo(jsVal: JsValue, idp: IdentityProvider)
        : OpenAuthDetails Or ErrMsg = tryParseGoodBad {

    // For now:
    // userid: null, first_name, last_name, country, city, company, job_function: '',
    // job_title: '', email

    val jsObj = asJsObject(jsVal, what = "Identity Provider custom user info")

    val email = parseSt(jsObj, "email")
    val userIdAtProvider = email  // for now
    val username = email.takeWhile(_ != '@')
    val firstName = parseOptSt(jsObj, "first_name")
    val lastName = parseOptSt(jsObj, "last_name")
    val firstSpaceLast = s"${firstName.getOrElse("")} ${lastName.getOrElse("")}"

    Good(OpenAuthDetails(
          serverDefaultIdpId = None,
          siteCustomIdpId = Some(idp.id_c),
          idpUserId = userIdAtProvider,
          username = Some(username),
          firstName = firstName,
          lastName = lastName,
          fullName = firstSpaceLast.trimNoneIfEmpty,
          email = Some(email),
          isEmailVerifiedByIdp = Some(false),
          avatarUrl = None,
          userInfoJson = Some(jsObj)))
  }

}
