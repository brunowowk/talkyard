/*
 * Copyright (C) 2014 Kaj Magnus Lindberg (born 1979)
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

/// <reference path="ReactDispatcher.ts" />
/// <reference path="ReactActions.ts" />
/// <reference path="../typedefs/lodash/lodash.d.ts" />

//------------------------------------------------------------------------------
   module debiki2 {
//------------------------------------------------------------------------------

// DefinitelyTyped has defined EventEmitter2 in the wrong module? Unusable when
// not using AMD/CommonJS, see https://github.com/borisyankov/DefinitelyTyped/issues/3075.
var EventEmitter2: any = window['EventEmitter2'];

var ChangeEvent = 'ChangeEvent';

export var ReactStore = new EventEmitter2();


// First, initialize the store with page specific data only, nothing user specific,
// because the server serves cached HTML with no user specific data. Later on,
// we'll insert user specific data into the store, and re-render. See
// ReactStore.activateUserSpecificData().
var store: Store = debiki.reactPageStore;


ReactDispatcher.register(function(payload) {
  var action = payload.action;
  switch (action.actionType) {

    case ReactActions.actionTypes.Login:
      ReactStore.activateUserSpecificData(action.user);
      break;

    case ReactActions.actionTypes.Logout:
      if (store.userMustBeAuthenticated !== false || store.userMustBeApproved !== false)
        location.reload();

      $('html').removeClass('dw-is-admin, dw-is-staff');

      store.user = {
        userId: undefined,
        permsOnPage: {},
        rolePageSettings: {},
        votes: {},
        unapprovedPosts: {},
        postIdsAutoReadLongAgo: [],
        postIdsAutoReadNow: [],
        marksByPostId: {},
      };
      break;

    case ReactActions.actionTypes.NewUserAccountCreated:
      store.newUserAccountCreated = true;
      break;

    case ReactActions.actionTypes.SetPageNotfLevel:
      store.user.rolePageSettings.notfLevel = action.newLevel;
      break;

    case ReactActions.actionTypes.UpdatePost:
      updatePost(action.post);
      break;

    case ReactActions.actionTypes.VoteOnPost:
      voteOnPost(action);
      break;

    case ReactActions.actionTypes.MarkPostAsRead:
      markPostAsRead(action.postId, action.manually);
      break;

    case ReactActions.actionTypes.CycleToNextMark:
      cycleToNextMark(action.postId);
      break;

    case ReactActions.actionTypes.SummarizeReplies:
      summarizeReplies();
      break;

    case ReactActions.actionTypes.CollapseTree:
      collapseTree(action.post);
      break;

    case ReactActions.actionTypes.UncollapsePost:
      uncollapsePost(action.post);
      break;

    case ReactActions.actionTypes.SetHorizontalLayout:
      store.horizontalLayout = action.enabled;
      break;

    case ReactActions.actionTypes.ChangeSiteStatus:
      store.siteStatus = action.newStatus;
      break;

    default:
      console.warn('Unknown action: ' + JSON.stringify(action));
      return true;
  }

  ReactStore.emitChange();
  store.quickUpdate = false;

  // Tell the dispatcher that there were no errors:
  return true;
});


// COULD change this to an action instead
ReactStore.activateUserSpecificData = function(anyUser) {
  store.userSpecificDataAdded = true;
  store.now = new Date().getTime();

  var newUser = anyUser || debiki.reactUserStore;
  if (!newUser) {
    // For now only. Later on, this data should be kept server side instead?
    addLocalStorageData(store.user);
    this.emitChange();
    return;
  }

  if (newUser.isAdmin) {
    $('html').addClass('dw-is-admin, dw-is-staff');
  }

  store.user = newUser;
  addLocalStorageData(store.user);

  // Show the user's own unapproved posts, or all, for admins.
  _.each(store.user.unapprovedPosts, (post: Post) => {
    updatePost(post);
  });

  store.quickUpdate = false;
  this.emitChange();
};


ReactStore.allData = function() {
  return store;
};


ReactStore.isGuestLoginAllowed = function() {
  return store.guestLoginAllowed || false;
}

ReactStore.getPageId = function() {
  return store.pageId;
}


ReactStore.getPageRole = function() {
  return store.pageRole;
}


ReactStore.getUser = function() {
  return store.user;
};


ReactStore.getCategories = function() {
  return store.categories;
};


ReactStore.emitChange = function() {
  this.emit(ChangeEvent);
};


ReactStore.addChangeListener = function(callback) {
  this.on(ChangeEvent, callback);
};


ReactStore.removeChangeListener = function(callback) {
  this.removeListener(ChangeEvent, callback);
};


export var StoreListenerMixin = {
  componentWillMount: function() {
    ReactStore.addChangeListener(this.onChange);
  },

  componentWillUnmount: function() {
    ReactStore.removeChangeListener(this.onChange);
  }
};


function clonePost(postId: number): Post {
  return _.cloneDeep(store.allPosts[postId]);
}


function updatePost(post: Post, isCollapsing?: boolean) {
  // (Could here remove any old version of the post, if it's being moved to
  // elsewhere in the tree.)

  store.now = new Date().getTime();

  var oldVersion = store.allPosts[post.postId];
  if (oldVersion && !isCollapsing) {
    // If we've modified-saved-reloaded-from-the-server this post, then ignore the
    // collapse settings from the server, in case the user has toggled it client side.
    // If `isCollapsing`, however, then we're toggling that state client side only.
    post.isTreeCollapsed = oldVersion.isTreeCollapsed;
    post.isPostCollapsed = oldVersion.isPostCollapsed;
  }
  else {
    store.numPosts += 1;
    if (post.postId !== TitleId) {
      store.numPostsExclTitle += 1;
    }
  }

  // Add or update the post itself.
  store.allPosts[post.postId] = post;

  // In case this is a new post, update its parent's child id list.
  var parentPost = store.allPosts[post.parentId];
  if (parentPost) {
    var alreadyAChild =
        _.find(parentPost.childIdsSorted, childId => childId === post.postId);
    if (!alreadyAChild) {
      parentPost.childIdsSorted.unshift(post.postId);
      sortPostIdsInPlace(parentPost.childIdsSorted, store.allPosts);
    }
  }

  // Update list of top level comments, for embedded comment pages.
  if (!post.parentId && post.postId != BodyPostId && post.postId !== TitleId) {
    store.topLevelCommentIdsSorted = topLevelCommentIdsSorted(store.allPosts);
  }

  rememberPostsToQuickUpdate(post.postId);
}


function voteOnPost(action) {
  var post: Post = action.post;

  var votes = store.user.votes[post.postId];
  if (!votes) {
    votes = [];
    store.user.votes[post.postId] = votes;
  }

  if (action.doWhat === 'CreateVote') {
    votes.push(action.voteType);
  }
  else {
    _.remove(votes, (voteType) => voteType === action.voteType);
  }

  updatePost(post);
}


function markPostAsRead(postId: number, manually: boolean) {
  var currentMark = store.user.marksByPostId[postId];
  if (currentMark) {
    // All marks already mean that the post has been read. Do nothing.
  }
  else if (manually) {
    store.user.marksByPostId[postId] = ManualReadMark;
  }
  else {
    store.user.postIdsAutoReadNow.push(postId);
  }
  rememberPostsToQuickUpdate(postId);
}


var lastPostIdMarkCycled = null;

function cycleToNextMark(postId: number) {
  var currentMark = store.user.marksByPostId[postId];
  var nextMark;
  // The first time when clicking the star icon, try to star the post,
  // rather than marking it as read or unread. However, when the user
  // continues clicking the same star icon, do cycle through the
  // read and unread states too. Logic: People probably expect the comment
  // to be starred on the very first click. The other states that happen
  // if you click the star even more, are for advanced users — don't need
  // to show them directly.
  if (lastPostIdMarkCycled !== postId) {
    if (!currentMark || currentMark === ManualReadMark) {
      nextMark = FirstStarMark;
    }
    else if (currentMark < LastStarMark) {
      nextMark = currentMark + 1;
    }
    else {
      nextMark = ManualReadMark;
    }
  }
  else {
    if (currentMark === ManualReadMark) {
      nextMark = null;
    }
    else if (!currentMark) {
      nextMark = FirstStarMark;
    }
    else if (currentMark < LastStarMark) {
      nextMark = currentMark + 1;
    }
    else {
      nextMark = ManualReadMark;
    }
  }
  lastPostIdMarkCycled = postId;
  store.user.marksByPostId[postId] = nextMark;

  rememberPostsToQuickUpdate(postId);
}


function summarizeReplies() {
  // For now, just collapse all threads with depth >= 2, if they're too long
  // i.e. they have successors, or consist of a long (high) comment.
  _.each(store.allPosts, (post: Post) => {
    if (post.postId === BodyPostId || post.postId === TitleId || post.parentId === BodyPostId)
      return;

    // Also see height in debiki-play.styl. [5E7PKW2]
    var isTooHigh = () => $('#post-' + post.postId).height() > 150;
    if (post.childIdsSorted.length || isTooHigh()) {
      post.isTreeCollapsed = 'Truncated';
    }
  });
}


function collapseTree(post: Post) {
  post = clonePost(post.postId);
  post.isTreeCollapsed = true;
  updatePost(post, true);
}


function uncollapsePost(post: Post) {
  post = clonePost(post.postId);
  post.isTreeCollapsed = false;
  post.isPostCollapsed = false;
  updatePost(post, true);
}


function topLevelCommentIdsSorted(allPosts): number[] {
  var idsSorted: number[] = [];
  _.each(allPosts, (post: Post) => {
    if (!post.parentId && post.postId !== BodyPostId && post.postId !== TitleId) {
      idsSorted.push(post.postId);
    }
  });
  sortPostIdsInPlace(idsSorted, allPosts);
  return idsSorted;
}


/**
 * NOTE: Keep in sync with sortPostsFn() in
 *   modules/debiki-core/src/main/scala/com/debiki/core/Post.scala
 */
function sortPostIdsInPlace(postIds: number[], allPosts) {
  postIds.sort((idA: number, idB: number) => {
    var postA = allPosts[idA];
    var postB = allPosts[idB];

    // Perhaps the server shouldn't include deleted comments in the children list?
    // Is that why they're null sometimes? COULD try to find out
    if (!postA && !postB)
      return 0;
    if (!postB)
      return -1;
    if (!postA)
      return +1;

    /* From app/debiki/HtmlSerializer.scala:
    if (a.pinnedPosition.isDefined || b.pinnedPosition.isDefined) {
      // 1 means place first, 2 means place first but one, and so on.
      // -1 means place last, -2 means last but one, and so on.
      val aPos = a.pinnedPosition.getOrElse(0)
      val bPos = b.pinnedPosition.getOrElse(0)
      assert(aPos != 0 || bPos != 0)
      if (aPos == 0) return bPos < 0
      if (bPos == 0) return aPos > 0
      if (aPos * bPos < 0) return aPos > 0
      return aPos < bPos
    } */

    // Place deleted posts last; they're rather uninteresting?
    if (!isDeleted(postA) && isDeleted(postB))
      return -1;

    if (isDeleted(postA) && !isDeleted(postB))
      return +1;

    // Place multireplies after normal replies. And sort multireplies by time,
    // for now, so it never happens that a multireply ends up placed before another
    // multireply that it replies to.
    // COULD place interesting multireplies first, if they're not constrained by
    // one being a reply to another.
    if (postA.multireplyPostIds.length && postB.multireplyPostIds.length) {
      if (postA.createdAt < postB.createdAt)
        return -1;
      if (postA.createdAt > postB.createdAt)
        return +1;
    }
    else if (postA.multireplyPostIds.length) {
      return +1;
    }
    else if (postB.multireplyPostIds.length) {
      return -1;
    }

    // Place interesting posts first.
    if (postA.likeScore > postB.likeScore)
      return -1;

    if (postA.likeScore < postB.likeScore)
      return +1

    // Newest posts first. No, last
    if (postA.createdAt < postB.createdAt)
      return -1;
    else
      return +1;
  });
}


/**
 * This data should be stored server side, but right now I'm prototyping only and
 * storing it client side only.
 */
function addLocalStorageData(user: User) {
  user.postIdsAutoReadLongAgo = sidebar.UnreadCommentsTracker.getPostIdsAutoReadLongAgo();
  user.marksByPostId = {}; // not implemented: loadMarksFromLocalStorage();
}


function loadMarksFromLocalStorage(): { [postId: number]: any } {
  return {};
}


function saveMarksInLocalStorage(marks: { [postId: number]: any }) {
  //...
}


function rememberPostsToQuickUpdate(startPostId: number) {
  store.quickUpdate = true;
  store.postsToUpdate = {};
  var post = store.allPosts[startPostId];
  while (post) {
    store.postsToUpdate[post.postId] = true;
    post = store.allPosts[post.parentId];
  }
}

//------------------------------------------------------------------------------
   }
//------------------------------------------------------------------------------
// vim: fdm=marker et ts=2 sw=2 tw=0 list
