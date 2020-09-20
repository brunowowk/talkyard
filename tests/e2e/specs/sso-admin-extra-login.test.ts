/// <reference path="../test-types.ts"/>

import * as _ from 'lodash';
import assert = require('assert');
import server = require('../utils/server');
//import utils = require('../utils/utils');
import { buildSite } from '../utils/site-builder';
import { TyE2eTestBrowser } from '../utils/pages-for';
//import settings = require('../utils/settings');
//import logAndDie = require('../utils/log-and-die');
//import c = require('../test-constants');


//declare var browserA: any;

let everyonesBrowsers;
let richBrowserA;
let owen: Member;
let owensBrowser: TyE2eTestBrowser;
let modya: Member;
let modyasBrowser: TyE2eTestBrowser;
let maria: Member;
let mariasBrowser: TyE2eTestBrowser;

let siteIdAddress: IdAddress;
let siteId;

let forum: LargeTestForum;

let discussionPageUrl: string;


describe("sso-admin-extra-login  TyT03WKDTRP50", () => {

  it("import a site", () => {
    const builder = buildSite();
    const site = builder.getSite();
    site.settings.enableApi = true;
    forum = builder.addLargeForum({
      title: "Some E2E Test",
      members: undefined, // default = everyone
    });
    assert(builder.getSite() === forum.siteData);
    siteIdAddress = server.importSiteData(forum.siteData);
    siteId = siteIdAddress.id;
    discussionPageUrl = siteIdAddress.origin + '/' + forum.topics.byMichaelCategoryA.slug;
  });

  it("initialize people", () => {
    everyonesBrowsers = new TyE2eTestBrowser(wdioBrowser);
    richBrowserA = everyonesBrowsers;

    owen = forum.members.owen;
    owensBrowser = richBrowserA;
    modya = forum.members.modya;
    modyasBrowser = richBrowserA;
    maria = forum.members.maria;
    mariasBrowser = richBrowserA;
  });

  it("Maria goes to the admin extra login page", () => {
    mariasBrowser.adminArea.goToAdminExtraLogin(siteIdAddress.origin);
  });

  it("... submits her email", () => {
    mariasBrowser.adminArea.adminExtraLogin.submitEmailAddress(maria.emailAddress);
  });

  it("... she gets an error message that there's no such admin email", () => {
    mariasBrowser.adminArea.adminExtraLogin.assertIsBadEmailAddress();

  });

  it("Owen submits his email, with at typo", () => {
    owensBrowser.adminArea.goToAdminExtraLogin();
    owensBrowser.adminArea.adminExtraLogin.submitEmailAddress('typo' + owen.emailAddress);
  });

  it("... he gets an error message that there's no such admin email", () => {
    owensBrowser.adminArea.adminExtraLogin.assertIsBadEmailAddress();
  });

  it("Owen submits his email, no typo", () => {
    owensBrowser.adminArea.goToAdminExtraLogin();
    owensBrowser.adminArea.adminExtraLogin.submitEmailAddress(owen.emailAddress);
  });

  it("... works fine, ok message", () => {
    owensBrowser.adminArea.adminExtraLogin.assertEmailSentMessage();
  });

  let oneTimeLoginLink;

  it("... he gets an email with a login link", () => {
    oneTimeLoginLink = server.waitAndGetOneTimeLoginLinkEmailedTo(siteId, owen.emailAddress, browser);
  });

  it("... clicks the link", () => {
    owensBrowser.go(oneTimeLoginLink);
  });

  it("... gets logged in, as admin", () => {
    const username = owensBrowser.topbar.getMyUsername();
    assert.equal(username, owen.username);
  });

  it("... and sees his user profile page", () => {
    owensBrowser.userProfilePage.assertUsernameIs(owen.username);
    owensBrowser.userProfilePage.assertIsMyProfile();
  });

  // SEC_TESTS_MISSING verify link expires after one hour

});

