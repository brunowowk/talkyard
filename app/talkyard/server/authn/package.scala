package talkyard.server

import com.debiki.core.Prelude.stringToRichString
import com.debiki.core.{ErrMsg, GetOrBadMap, IdentityProvider, OpenAuthDetails}
import debiki.JsonUtils._
import org.scalactic.{Bad, Good, Or}
import play.api.libs.json.JsValue
import talkyard.server.authn.OidcClaims.parseOidcClaims


package object authn {


  def parseOidcUserInfo(json: JsValue, idp: IdentityProvider)
        : OpenAuthDetails Or ErrMsg = {
    val claims = parseOidcClaims(json) getOrIfBad { errMsg =>
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
          providerId = idp.id_c.toString,
          providerKey = claims.sub,
          idpDatabaseId = Some(idp.id_c),
          isThisSiteCustomIdp = true,
          username = claims.preferred_username,
          firstName = claims.given_name,
          lastName = claims.family_name,
          fullName = anyName,
          email = claims.email,
          isEmailVerifiedByIdp = Some(claims.email_verified),
          avatarUrl = claims.picture,
          userInfoJson = Some(json)))
  }


  def parseCustomUserInfo(json: JsValue, idp: IdentityProvider)
        : OpenAuthDetails Or ErrMsg = tryParseGoodBad {

    // For now:
    // userid: null, first_name, last_name, country, city, company, job_function: '',
    // job_title: '', email

    val email = parseSt(json, "email")
    val userIdAtProvider = email  // for now
    val username = email.takeWhile(_ != '@')
    val firstName = parseOptSt(json, "first_name")
    val lastName = parseOptSt(json, "last_name")
    val firstSpaceLast = s"${firstName.getOrElse("")} ${lastName.getOrElse("")}"

    Good(OpenAuthDetails(
          providerId = idp.id_c.toString,
          providerKey = userIdAtProvider,
          idpDatabaseId = Some(idp.id_c),
          isThisSiteCustomIdp = true,
          username = Some(username),
          firstName = firstName,
          lastName = lastName,
          fullName = firstSpaceLast.trimNoneIfEmpty,
          email = Some(email),
          isEmailVerifiedByIdp = Some(false),
          avatarUrl = None,
          userInfoJson = Some(json)))
  }

}
