// Room Management Socket Events Reference
// Copy these examples into your client-side JavaScript

/* ========================================
   ROOM OWNERSHIP - Owner Only
   ======================================== */

// Rename a room
socket.emit('room:rename', {
  roomName: 'current-room-name',
  newName: 'new-room-name'
}, (response) => {
  if (response.ok) {
    console.log(`Room renamed from ${response.oldName} to ${response.newName}`);
  } else {
    console.error('Rename failed:', response.error);
  }
});

// Promote user to admin
socket.emit('room:promote', {
  roomName: 'my-room',
  userId: 123,
  role: 'admin'  // or 'helper'
}, (response) => {
  if (response.ok) {
    console.log('User promoted to', response.role);
  } else {
    console.error('Promotion failed:', response.error);
  }
});

// Demote a user (remove their admin/helper role)
socket.emit('room:demote', {
  roomName: 'my-room',
  userId: 123
}, (response) => {
  if (response.ok) {
    console.log('User demoted');
  } else {
    console.error('Demotion failed:', response.error);
  }
});

/* ========================================
   ROOM MODERATION - Owner & Admin
   ======================================== */

// Ban a user from the room
socket.emit('room:ban', {
  roomName: 'my-room',
  userId: 456,
  duration: '24h',  // See duration options below
  reason: 'Spam posting'  // Optional
}, (response) => {
  if (response.ok) {
    console.log('User banned until', new Date(response.expiresAt));
  } else {
    console.error('Ban failed:', response.error);
  }
});

// Duration options for bans:
// Admins can use: '5m', '10m', '30m', '1h', '2h', '4h', '8h', '24h', '7d'
// Only owners can use: '30d', '6mo', '1y', 'forever'
// Note: Only room owners can ban for more than 7 days

// Unban a user
socket.emit('room:unban', {
  roomName: 'my-room',
  userId: 456
}, (response) => {
  if (response.ok) {
    console.log('User unbanned');
  } else {
    console.error('Unban failed:', response.error);
  }
});

// View all room bans (owner/admin only)
socket.emit('room:bans', {
  roomName: 'my-room'
}, (response) => {
  if (response.ok) {
    response.bans.forEach(ban => {
      console.log(`${ban.username} banned by ${ban.banned_by}`);
      console.log(`Reason: ${ban.reason}`);
      console.log(`Expires: ${ban.expires_at ? new Date(ban.expires_at) : 'Never'}`);
    });
  } else {
    console.error('Failed to fetch bans:', response.error);
  }
});

/* ========================================
   ROOM INFORMATION - All Users
   ======================================== */

// View room members and their roles
socket.emit('room:members', {
  roomName: 'my-room'
}, (response) => {
  if (response.ok) {
    response.members.forEach(member => {
      console.log(`${member.username}: ${member.role}`);
      // Roles: 'owner', 'admin', 'helper'
    });
  } else {
    console.error('Failed to fetch members:', response.error);
  }
});

/* ========================================
   CLIENT-SIDE EVENT LISTENERS
   ======================================== */

// Listen for room ban notification (when you're banned)
socket.on('room:banned', ({ roomName, reason, expiresAt }) => {
  const expiry = expiresAt ? new Date(expiresAt) : 'permanent';
  alert(`You've been banned from ${roomName}. Reason: ${reason}. Expires: ${expiry}`);
  // Redirect to main room or handle as needed
});

/* ========================================
   UI EXAMPLE - Room Settings Panel
   ======================================== */

function showRoomSettings(roomName, userRole) {
  // Only show owner/admin controls if user has permission
  if (userRole === 'owner') {
    // Show: Rename, Promote, Demote, Ban, Unban, View Members, View Bans
    return `
      <div class="room-settings">
        <h3>Room Settings</h3>
        <button onclick="renameRoom()">Rename Room</button>
        <button onclick="manageMembers()">Manage Members</button>
        <button onclick="viewBans()">View Bans</button>
      </div>
    `;
  } else if (userRole === 'admin') {
    // Show: Ban, Unban, View Members, View Bans
    return `
      <div class="room-settings">
        <h3>Room Moderation</h3>
        <button onclick="viewBans()">View Bans</button>
        <button onclick="banUser()">Ban User</button>
      </div>
    `;
  }
  return ''; // Regular users don't see settings
}

/* ========================================
   PERMISSION CHECKING
   ======================================== */

// Get current user's role in the room
socket.emit('room:members', { roomName: 'current-room' }, (response) => {
  if (response.ok) {
    const currentUserId = getCurrentUserId(); // Your function to get user ID
    const myMembership = response.members.find(m => m.user_id === currentUserId);
    const myRole = myMembership ? myMembership.role : null;
    
    // Update UI based on role
    updateRoomSettingsUI(myRole);
  }
});

/* ========================================
   BAN DURATION HELPER
   ======================================== */

function getBanDurationOptions() {
  return [
    { value: '5m', label: '5 minutes', ownerOnly: false },
    { value: '10m', label: '10 minutes', ownerOnly: false },
    { value: '30m', label: '30 minutes', ownerOnly: false },
    { value: '1h', label: '1 hour', ownerOnly: false },
    { value: '2h', label: '2 hours', ownerOnly: false },
    { value: '4h', label: '4 hours', ownerOnly: false },
    { value: '8h', label: '8 hours', ownerOnly: false },
    { value: '24h', label: '24 hours', ownerOnly: false },
    { value: '7d', label: '7 days', ownerOnly: false },
    { value: '30d', label: '30 days (Owner only)', ownerOnly: true },
    { value: '6mo', label: '6 months (Owner only)', ownerOnly: true },
    { value: '1y', label: '1 year (Owner only)', ownerOnly: true },
    { value: 'forever', label: 'Permanent (Owner only)', ownerOnly: true }
  ];
}

// Filter ban options based on user role
function getBanDurationOptionsForRole(userRole) {
  const allOptions = getBanDurationOptions();
  if (userRole === 'owner') {
    return allOptions; // Owners can use all durations
  }
  // Admins can only use durations up to 7 days
  return allOptions.filter(opt => !opt.ownerOnly);
}

/* ========================================
   ERROR HANDLING
   ======================================== */

function handleRoomManagementError(error, action) {
  const errorMessages = {
    'Not authenticated': 'Please log in to perform this action',
    'Missing parameters': 'Invalid request - please try again',
    'Invalid role': 'Invalid role specified',
    'Only room owner can': 'You must be the room owner to do this',
    'Only room owner or admin can': 'You must be owner or admin to do this',
    'Only room owner can ban for more than 7 days': 'Only the room owner can issue bans longer than 7 days',
    'Room name already exists': 'A room with that name already exists',
    'Permission denied': 'You do not have permission to do this'
  };
  
  const userMessage = errorMessages[error] || `Failed to ${action}: ${error}`;
  console.error(userMessage);
  // Display to user via toast/alert/notification
  showNotification(userMessage, 'error');
}
