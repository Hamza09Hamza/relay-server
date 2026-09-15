const users = require('./users');
const rooms = require('./rooms');
const messages = require('./messages');
const calls = require('./calls');
const recordings = require('./recordings');
const recordingJobs = require('./recordingJobs');
const workspaces = require('./workspaces');
const userWorkspaces = require('./userWorkspaces');
const refreshTokens = require('./refreshTokens');
const scheduledConferences = require('./scheduledConferences');
const roomNotificationModes = require('./roomNotificationModes');
const conferenceArchives = require('./conferenceArchives');

module.exports = {
  users,
  rooms,
  messages,
  calls,
  recordings,
  recordingJobs,
  workspaces,
  userWorkspaces,
  refreshTokens,
  scheduledConferences,
  roomNotificationModes,
  conferenceArchives,
};
