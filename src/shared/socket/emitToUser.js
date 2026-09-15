/**
 * emitToUser — emit an event to every live socket belonging to a user
 * (handles multiple tabs / devices). Factory because the Socket.IO server
 * instance is created in server.js.
 *
 * Each socket joins the room `user:<userId>` on registration (see server.js),
 * so this is an O(1) room emit rather than a scan over every connected socket,
 * and it fans out across all instances when the Redis adapter is active.
 */
function createEmitToUser(io) {
  return function emitToUser(userId, event, data) {
    if (userId === null || userId === undefined) return;
    io.to('user:' + userId).emit(event, data);
  };
}

module.exports = { createEmitToUser };
