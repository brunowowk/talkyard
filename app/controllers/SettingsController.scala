/**
 * Copyright (c) 2014-2016 Kaj Magnus Lindberg
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
import debiki._
import debiki.EdHttp._
import ed.server.{EdContext, EdController}
import ed.server.http._
import javax.inject.Inject
import play.api.libs.json._
import play.api.mvc.{Result => p_Result}
import play.api.mvc.{Action, ControllerComponents}
import talkyard.server.JsX
import talkyard.server.sitepatch.SitePatchParser


/** Loads and saves settings, for the whole website, site sections,
  * and individual pages. In the future probably also for user roles.
  */
class SettingsController @Inject()(cc: ControllerComponents, edContext: EdContext)
  extends EdController(cc, edContext) {

  import context.globals

  /** Later, maybe don't show all settings to moderators, in case there'll be
    * some private settings, later on. (Currently, there aren't.) [5KBRQT2]
    */
  def loadSiteSettings: Action[Unit] = StaffGetAction { request: GetRequest =>
    loadSiteSettingsImpl(request)
  }


  private def loadSiteSettingsImpl(request: DebikiRequest[_]): p_Result = {
    val settings = request.dao.getWholeSiteSettings()
    // What's the default, if settings from parent categories have been inherited? Therefore:
    dieIf(settings.editedSettingsChain.length > 1, "EsE4GJKU0", "not tested")
    OkSafeJson(Json.obj(
      "effectiveSettings" -> settings.toJson,
      "defaultSettings" -> settings.default.toJson,
      "baseDomain" -> globals.baseDomainNoPort,
      "dnsCnameTargetHost" -> JsString(globals.config.dnsCnameTargetHost.getOrElse(
          s"? (config value ${Config.DnsCnameTargetHostConfValName} missing [EsM5KGCJ2]) ?")),
      "hosts" -> request.dao.listHostnames().sortBy(_.hostname).map(host => {
        Json.obj("hostname" -> host.hostname, "role" -> host.role.IntVal)
      })
    ))
  }


  /** Moderators may not change any settings.
    *
    * Why up to 50k? Because some html settings can include inline SVG,
    * and an SVG logo can be like 10 kb so 10 is too little.
    * Later: Could move such html to  t_extensions,  for e.g. themes and
    * custom html incl svg. [extensions]
    */
  def saveSiteSettings: Action[JsValue] = AdminPostJsonAction(maxBytes = 50*1000) {
        request: JsonPostRequest =>
    val settingsToSave = debiki.Settings2.settingsToSaveFromJson(request.body, globals)
    request.dao.saveSiteSettings(settingsToSave, request.who)
    loadSiteSettingsImpl(request)
  }


  def changeHostname: Action[JsValue] = AdminPostJsonAction(maxBytes = 100) {
          request: JsonPostRequest =>
    val newHostname = (request.body \ "newHostname").as[String]
    request.dao.changeSiteHostname(newHostname)
    Ok
  }


  def updateExtraHostnames: Action[JsValue] = AdminPostJsonAction(maxBytes = 50) {
        request: JsonPostRequest =>
    val redirect = (request.body \ "redirect").as[Boolean]
    val role = if (redirect) Hostname.RoleRedirect else Hostname.RoleDuplicate
    request.dao.changeExtraHostsRole(newRole = role)
    Ok
  }


  def loadOidcConfig: Action[Unit] = StaffGetAction { request: GetRequest =>
    loadOidcConfigImpl(request,
          inclSecret = true)  // later: Add a "briefNoSecrets=true" param, then excl secret?
  }


  def upsertOidcConfig: Action[JsValue] = AdminPostJsonAction(maxBytes = 2000) {
          request: JsonPostRequest =>
    import request.{dao, body}
    val idpsJsonArr = body.asOpt[JsArray].getOrThrowBadRequest(
          "TyE406WKTDW2", "I want a json array with IDP configs")
    val parser = SitePatchParser(context)
    val idps: Seq[IdentityProvider] = idpsJsonArr.value map { idp =>
      parser.readIdentityProviderorBad(idp) getOrIfBad { problem =>
        throwBadRequest("TyE703RKT4j7", s"Bad IDP json: $problem")
      }
    }
    dao.writeTx { (tx, _) =>
      idps foreach tx.upsertIdentityProvider
      // Later: Uncache only those that got changed.
      dao.uncacheAuthnServices(idps)
    }
    loadOidcConfigImpl(request, inclSecret = true)
  }


  private def loadOidcConfigImpl(request: DebikiRequest[_], inclSecret: Boolean): p_Result = {
    val idps = request.dao.readTx(_.loadAllIdentityProviders())
          .sortBy(idp => idp.gui_order_c getOrElse (idp.id_c + 1000 * 1000))
    val json = JsArray(idps map JsX.JsIdentityProviderSecretConf)
    OkSafeJson(json)
  }

}

