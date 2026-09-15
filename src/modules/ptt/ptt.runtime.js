'use strict';

// REST membership changes and Socket.IO live state are initialized at
// different points in server.js. This tiny singleton is the bridge: routes can
// synchronously revoke a live listener without importing server.js or keeping a
// second presence registry.
let controller = null;

function install(nextController) {
  controller = nextController || null;
}

async function evictUser(channelId, userId, reason = 'access_revoked') {
  return controller?.evictUser?.(channelId, userId, reason);
}

async function refreshUserAccess(channelId, userId) {
  return controller?.refreshUserAccess?.(channelId, userId);
}

async function evictChannel(channelId, reason = 'channel_deleted') {
  return controller?.evictChannel?.(channelId, reason);
}

async function evictUserFromWorkspace(workspaceId, userId, reason = 'workspace_access_revoked') {
  return controller?.evictUserFromWorkspace?.(workspaceId, userId, reason);
}

async function evictWorkspace(workspaceId, reason = 'workspace_deleted') {
  return controller?.evictWorkspace?.(workspaceId, reason);
}

async function cancelWorkspaceDeletion(workspaceId) {
  return controller?.cancelWorkspaceDeletion?.(workspaceId);
}

async function evictUserEverywhere(userId, reason = 'account_access_revoked') {
  return controller?.evictUserEverywhere?.(userId, reason);
}

module.exports = {
  install,
  evictUser,
  refreshUserAccess,
  evictChannel,
  evictUserFromWorkspace,
  evictWorkspace,
  cancelWorkspaceDeletion,
  evictUserEverywhere,
};
