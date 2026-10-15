// @orkestia/auth — identity workspace workflow contract helpers.

import test from "node:test";
import assert from "node:assert/strict";
import {
  IDENTITY_WORKFLOW_TYPES,
  buildAppOrganizationAssignRoleInput,
  buildAppOrganizationCreateInput,
  buildAppOrganizationMemberInput,
  buildAppOrganizationQueryInput,
  buildAppSetOrgOwnedInput,
  buildEndUserOrganizationGetInput,
  buildEndUserOrganizationSwitchInput,
} from "../dist/index.js";

test("identity workspace workflow type names match production", () => {
  assert.deepEqual(IDENTITY_WORKFLOW_TYPES, {
    endUserWhoami: "identity.end-user.whoami",
    endUserOrganizationQuery: "identity.end-user.organization.query",
    endUserOrganizationGet: "identity.end-user.organization.get",
    endUserOrganizationSwitch: "identity.end-user.organization.switch",
    appOrganizationCreate: "identity.app-organization.create",
    appOrganizationQuery: "identity.app-organization.query",
    appOrganizationAddMember: "identity.app-organization.add-member",
    appOrganizationInvite: "identity.app-organization.invite",
    appOrganizationAssignRole: "identity.app-organization.assign-role",
    appSetOrgOwned: "identity.app.set-org-owned",
  });
});

test("end-user workspace builders use production field names", () => {
  assert.deepEqual(buildEndUserOrganizationGetInput({
    appOrganizationUuid: "workspace-1",
  }), {
    app_organization_uuid: "workspace-1",
  });

  assert.deepEqual(buildEndUserOrganizationSwitchInput({
    appOrganizationUuid: "workspace-1",
  }), {
    app_organization_uuid: "workspace-1",
  });
});

test("app organization admin builders use production field names", () => {
  assert.deepEqual(buildAppOrganizationCreateInput({
    identityAppUuid: "app-1",
    name: "DPWAI",
    slug: "dpwai",
    kind: "workspace",
    metadata: { source: "test" },
  }), {
    identity_app_uuid: "app-1",
    name: "DPWAI",
    slug: "dpwai",
    kind: "workspace",
    metadata: { source: "test" },
  });

  assert.deepEqual(buildAppOrganizationQueryInput({
    identityAppUuid: "app-1",
  }), {
    identity_app_uuid: "app-1",
  });

  assert.deepEqual(buildAppOrganizationMemberInput({
    identityAppUuid: "app-1",
    appOrganizationUuid: "workspace-1",
    email: "member@example.com",
    groupSlug: "admin",
  }), {
    identity_app_uuid: "app-1",
    app_organization_uuid: "workspace-1",
    email: "member@example.com",
    group_slug: "admin",
  });

  assert.deepEqual(buildAppOrganizationAssignRoleInput({
    identityAppUuid: "app-1",
    appOrganizationUuid: "workspace-1",
    endUserUuid: "user-1",
    groupSlug: "operator",
    force: true,
  }), {
    identity_app_uuid: "app-1",
    app_organization_uuid: "workspace-1",
    end_user_uuid: "user-1",
    group_slug: "operator",
    force: true,
  });

  assert.deepEqual(buildAppSetOrgOwnedInput({
    identityAppUuid: "app-1",
    orgOwnedEnabled: true,
  }), {
    identity_app_uuid: "app-1",
    org_owned_enabled: true,
  });
});
