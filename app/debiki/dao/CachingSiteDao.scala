/**
 * Copyright (C) 2012 Kaj Magnus Lindberg (born 1979)
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

package debiki.dao

import com.debiki.core._
import com.debiki.core.Prelude._
import java.{util => ju}
import play.{api => p}
import CachingDao.CacheKey



class CachingSiteDao(
  val siteId: SiteId,
  val dbDaoFactory: DbDaoFactory,
  val cache: DaoMemCache)
  extends SiteDao
  with CachingDao
  with CachingAssetBundleDao
  with CachingSpecialContentDao
  with CachingCategoriesDao
  with CachingPagesDao
  with CachingPagePathMetaDao
  with CachingPageStuffDao
  with CachingPostsDao
  with CachingRenderedPageHtmlDao
  with CachingWatchbarDao {

  def dbDao2 = dbDaoFactory.newDbDao2()

  protected def memCache = new MemCache(siteId, cache)


  onUserCreated { user =>
    if (loadSiteStatus().isInstanceOf[SiteStatus.OwnerCreationPending] && user.isOwner) {
      uncacheSiteStatus()
    }
  }

  onPageCreated { page =>
    if (loadSiteStatus() == SiteStatus.ContentCreationPending) {
      uncacheSiteStatus()
    }
  }


  override def refreshPageInAnyCache(pageId: PageId) {
    firePageSaved(SitePageId(siteId = siteId, pageId = pageId))
  }


  override def emptyCache() {
    readWriteTransaction(_.bumpSiteVersion())
    emptyCache(siteId)
  }


  def emptyCacheImpl(transaction: SiteTransaction) {
    transaction.bumpSiteVersion()
    emptyCache(siteId)
  }


  override def updateSite(changedSite: Site) = {
    super.updateSite(changedSite)
    uncacheSiteStatus()
  }


  override def loadSiteStatus(): SiteStatus = {
    lookupInCache(
      siteStatusKey,
      orCacheAndReturn = Some(super.loadSiteStatus())) getOrDie "DwE5CB50"
  }


  private def uncacheSiteStatus() {
    removeFromCache(siteStatusKey)
  }


  private def siteStatusKey = CacheKey(this.siteId, "|SiteId")


  // ---- For now only, whilst migrating to separate MemCache field:
  override def onPageCreated(callback: (PagePath => Unit)) {
    memCache.onPageCreated(callback)
    super.onPageCreated(callback)
  }
  override def firePageCreated(pagePath: PagePath) {
    memCache.firePageCreated(pagePath)
    super.firePageCreated(pagePath)
  }
  override def onPageSaved(callback: (SitePageId => Unit)) {
    memCache.onPageSaved(callback)
    super.onPageSaved(callback)
  }
  override def firePageSaved(sitePageId: SitePageId) {
    memCache.firePageSaved(sitePageId)
    super.firePageSaved(sitePageId)
  }
  override def onPageMoved(callback: (PagePath => Unit)) {
    memCache.onPageMoved(callback)
    super.onPageMoved(callback)
  }
  override def firePageMoved(newPath: PagePath) {
    memCache.firePageMoved(newPath)
    super.firePageMoved(newPath)
  }
  override def onUserCreated(callback: (User => Unit)) {
    memCache.onUserCreated(callback)
    super.onUserCreated(callback)
  }
  override def fireUserCreated(user: User) {
    memCache.fireUserCreated(user)
    super.fireUserCreated(user)
  }
  // ---- /End for-now-only

}
