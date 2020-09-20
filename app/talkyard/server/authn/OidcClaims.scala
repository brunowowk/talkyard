package talkyard.server.authn

import com.debiki.core.{Bo, ErrMsg, Opt, St, i64}
import debiki.JsonUtils._
import org.scalactic.{Good, Or}
import play.api.libs.json.{JsObject, JsValue}


/**
  * OIDC standard fields:
  * https://openid.net/specs/openid-connect-core-1_0.html#Claims
  */
case class OidcClaims(
  sub: St, // End user id at the provider
  name: Opt[St], // Full name, all name parts, and possibly titles and suffixes
  given_name: Opt[St], // (aka first name) Some people have many given names.
  family_name: Opt[St], // Surname(s) or last name(s), there can be one, many or none
  middle_name: Opt[St], // There can be one, many or none
  nickname: Opt[St],
  preferred_username: Opt[St], // Might incl weird chars like @ or whitespace.
      // Don't assume it's unique in any way.
  profile: Opt[St], // URL to the user's profile web page (at the provider, right)
  picture: Opt[St], // URL to profile photo of  user, must be an image file.
  website: Opt[St], // URL to user's web page or blog.
  email: Opt[St], // Preferred email address. Might not be unique.
  email_verified: Bo, // If the OpenID Provider some time in the past
  // somehow has verified that the user controlled the email address.
  gender: Opt[St], // "female" or "male" or something else.
  birthdate: Opt[St], // YYYY (date omitted) or YYYY-MM-DD.
  // Year 0000 means the year was omitted.
  zoneinfo: Opt[St], // Time zone, e.g. "Europe/Paris" or "America/Los_Angeles".
  locale: Opt[St], // BCP47 [RFC5646] language tag, typically like
  // en-US or en_US, that is,
  // first an ISO 639-1 Alpha-2 [ISO639‑1] language code, lowercase,
  // a dash (or sometimes an underscore)
  // then an ISO 3166-1 Alpha-2 [ISO3166‑1] country code, uppercase.
  phone_number: Opt[St], // The recommended format is called E.164, looks like:
  // +1 (425) 555-1212 or +56 (2) 687 2400.
  // If phone_number_verified, then, MUST be E.164 format.
  phone_number_verified: Bo, // Like email_verified.
  address: Opt[JsObject], // Preferred postal address, JSON [RFC4627]
  updated_at: Opt[i64])  // Unix time seconds since user info last updated.



object OidcClaims {

  def parseOidcClaims(json: JsValue): OidcClaims Or ErrMsg = tryParseGoodBad {
    Good(OidcClaims(
          sub = parseSt(json, "sub"),
          name = parseOptSt(json, "name"),
          given_name = parseOptSt(json, "given_name"),
          family_name = parseOptSt(json, "family_name"),
          middle_name = parseOptSt(json, "middle_name"),
          nickname = parseOptSt(json, "nickname"),
          preferred_username = parseOptSt(json, "preferred_username"),
          profile = parseOptSt(json, "profile"),
          picture = parseOptSt(json, "picture"),
          website = parseOptSt(json, "website"),
          email = parseOptSt(json, "email"),
          email_verified = parseBo(json, "email_verified", default = false),
          gender = parseOptSt(json, "gender"),
          birthdate = parseOptSt(json, "birthdate"),
          zoneinfo = parseOptSt(json, "zoneinfo"),
          locale = parseOptSt(json, "locale"),
          phone_number = parseOptSt(json, "phone_number"),
          phone_number_verified = parseBo(json, "phone_number_verified", default = false),
          address = parseOptJsObject(json, "address"),
          updated_at = parseOptLong(json, "updated_at")))
  }

}
