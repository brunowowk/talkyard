/*
 * Copyright (c) 2015-2016 Kaj Magnus Lindberg
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

/// <reference path="../../typedefs/react/react.d.ts" />
/// <reference path="../../typedefs/moment/moment.d.ts" />
/// <reference path="../plain-old-javascript.d.ts" />
/// <reference path="../ReactStore.ts" />
/// <reference path="../Server.ts" />
/// <reference path="../links.ts" />
/// <reference path="review-posts.ts" />

//------------------------------------------------------------------------------
   module debiki2.admin {
//------------------------------------------------------------------------------

var d = { i: debiki.internal, u: debiki.v0.util };
var r = React.DOM;
var reactCreateFactory = React['createFactory'];
var ReactBootstrap: any = window['ReactBootstrap'];
var Button = reactCreateFactory(ReactBootstrap.Button);
var Nav = reactCreateFactory(ReactBootstrap.Nav);
var NavItem = reactCreateFactory(ReactBootstrap.NavItem);


export var UsersTabComponent = React.createClass(<any> {
  getInitialState: function() {
    return {};
  },

  sendInvites: function() {
    var user = debiki2.ReactStore.getUser();
    window.location.assign(linkToInvitesFromUser(user.userId));
  },

  render: function() {
    return (
      r.div({},
        r.div({ className: 'dw-sub-nav' },
          r.div({ className: 'pull-right' },
            // Later: Change this to a tab that lists all invites sent by all users.
            // And in that tab, include a Send Invites button.
            Button({ onClick: this.sendInvites }, 'Send Invites')),
          Nav({ bsStyle: 'pills' },
            r.li({}, Link({ to: '/-/admin/users/active', activeClassName: 'active' }, "Active")),
            r.li({}, Link({ to: '/-/admin/users/new', activeClassName: 'active' }, "New Waiting")))),
            // with react-router-bootstrap, sth like:
            //   NavItem({ eventKey: 'users-new' }, 'New Waiting'))),   ?
        r.div({ className: 'dw-admin-panel' },
          React.cloneElement(this.props.children, { loggedInUser: this.props.loggedInUser }))));
  }
});


export var ActiveUsersPanelComponent = React.createClass({
  render: function() {
    return UserList({ whichUsers: 'ActiveUsers' });
  }
});


export var NewUsersPanelComponent = React.createClass({
  render: function() {
    return UserList({ whichUsers: 'NewUsers' });
  }
});


var UserList = createComponent({
  mixins: [SaveSettingMixin],

  componentDidMount: function() {
    Server.listCompleteUsers(this.props.whichUsers, users => {
      this.setState({ users: users });
    });
  },

  render: function() {
    if (!this.state)
      return r.p({}, 'Loading...');

    var now = new Date().getTime();
    var userRows = this.state.users.map((user: CompleteUser) => {
      return UserRow({ user: user, now: now, key: user.id, whichUsers: this.props.whichUsers });
    });

    var actionHeader = this.props.whichUsers === 'NewUsers'
        ? r.th({}, 'Actions')
        : null;

    return (
      r.div({ className: 'dw-users-to-review' },
        r.table({ className: 'table' },
          r.thead({},
            r.tr({},
              r.th({}, 'Username (Full Name)'),
              r.th({}, 'Email'),
              actionHeader,
              r.th({}, 'Country'),
              r.th({}, 'URL'),
              r.th({}, 'Created At'))),
          r.tbody({},
            userRows))));
  }
});


var UserRow = createComponent({
  getInitialState: function() {
    return {};
  },

  approveUser: function() {
    Server.approveRejectUser(this.props.user, 'Approve', () => {
      this.setState({ wasJustApproved: true });
    });
  },

  rejectUser: function() {
    Server.approveRejectUser(this.props.user, 'Reject', () => {
      this.setState({ wasJustRejected: true });
    });
  },

  undoApproveOrReject: function() {
    Server.approveRejectUser(this.props.user, 'Undo', () => {
      this.setState({ wasJustRejected: false, wasJustApproved: false });
    });
  },

  render: function() {
    var user: CompleteUser = this.props.user;

    var actions;
    if (this.props.whichUsers !== 'NewUsers') {
      // Don't show any actions.
    }
    else if (this.state.wasJustApproved) {
      actions = r.span({},
        'Approved.',
         Button({ onClick: this.undoApproveOrReject }, 'Undo'));
    }
    else if (this.state.wasJustRejected) {
      actions = r.span({},
        'Rejected.',
         Button({ onClick: this.undoApproveOrReject }, 'Undo'));
    }
    else {
      actions = r.span({},
          Button({ onClick: this.approveUser }, 'Approve'),
          Button({ onClick: this.rejectUser }, 'Reject'));
    }

    var actionsCell = actions
        ? r.td({}, actions)
        : null;

    var usernameElem = r.span({ className: 'dw-username' }, user.username);
    var fullNameElem;
    if (user.fullName) {
      fullNameElem = r.span({ className: 'dw-fullname' }, ' (' + user.fullName + ')');
    }

    return (
      r.tr({},
        r.td({},
          Link({ to: linkToUserInAdminArea(user.id) }, usernameElem, fullNameElem)),

        r.td({},
          user.email),

        actionsCell,

        r.td({},
          user.country),

        r.td({},
          user.url),

        r.td({},
          moment(user.createdAtEpoch).from(this.props.now))));
  }
});


//------------------------------------------------------------------------------
   }
//------------------------------------------------------------------------------
// vim: fdm=marker et ts=2 sw=2 tw=0 fo=r list
