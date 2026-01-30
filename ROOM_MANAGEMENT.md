# Room Management Implementation Summary

## Overview
This implementation adds comprehensive room management features to the chat application, allowing room owners to control their rooms and room admins to moderate users within rooms.

## Features Implemented

### 1. Database Schema
- **`room_members` table**: Tracks room roles (owner, admin, helper) for users
  - `id`: Primary key
  - `room_name`: Foreign key to rooms table
  - `user_id`: User ID
  - `role`: 'owner', 'admin', or 'helper'
  - `assigned_by_user_id`: Who assigned the role
  - `assigned_at`: Timestamp of assignment
  - Unique constraint on (room_name, user_id)
  - Cascade delete on room deletion

- **`room_bans` table**: Tracks room-specific bans with durations
  - `id`: Primary key
  - `room_name`: Foreign key to rooms table
  - `user_id`: Banned user ID
  - `banned_by_user_id`: Who issued the ban
  - `reason`: Optional ban reason
  - `banned_at`: Timestamp of ban
  - `expires_at`: Expiration timestamp (NULL = permanent)
  - Unique constraint on (room_name, user_id)
  - Cascade delete on room deletion

### 2. Room Ownership
- Room creator is automatically assigned as owner in `room_members` table
- Owners have full control over their room
- Only one owner per room

### 3. Room Management Socket Events

#### `room:rename`
- **Permission**: Owner only
- **Parameters**: `{ roomName, newName }`
- **Description**: Renames a room, updating all related tables
- **Validation**: Checks for duplicate names, sanitizes input

#### `room:promote`
- **Permission**: Owner only
- **Parameters**: `{ roomName, userId, role }` (role: 'admin' or 'helper')
- **Description**: Promotes a user to admin or helper role

#### `room:demote`
- **Permission**: Owner only
- **Parameters**: `{ roomName, userId }`
- **Description**: Removes a user's admin or helper role

#### `room:ban`
- **Permission**: Owner or Admin (with restrictions)
- **Parameters**: `{ roomName, userId, duration, reason }`
- **Durations**: '5m', '10m', '30m', '1h', '2h', '4h', '8h', '24h', '7d', '30d', '6mo', '1y', 'forever'
- **Restrictions**: 
  - Admins can ban for up to 7 days (5m, 10m, 30m, 1h, 2h, 4h, 8h, 24h, 7d)
  - Only owners can ban for more than 7 days (30d, 6mo, 1y, forever)
- **Description**: Bans a user from the room for a specified duration
- **Behavior**: Automatically kicks user if they're currently in the room

#### `room:unban`
- **Permission**: Owner or Admin
- **Parameters**: `{ roomName, userId }`
- **Description**: Removes a user's ban from the room

#### `room:members`
- **Permission**: Authenticated users
- **Parameters**: `{ roomName }`
- **Description**: Lists all members with roles in the room
- **Returns**: Array of members sorted by role (owner, admin, helper)

#### `room:bans`
- **Permission**: Owner or Admin
- **Parameters**: `{ roomName }`
- **Description**: Lists all active and expired bans in the room
- **Returns**: Array of bans with user info, reason, and expiration

### 4. Ban Enforcement
- Ban checking added to "join room" event handler
- Users banned from a room are redirected to main room
- Ban expiration is checked on each join attempt
- Expired bans remain in database for audit purposes

### 5. Helper Functions
- `getUserRoomRole(roomName, userId)`: Returns user's role in a room (owner, admin, helper, or null)
- `isUserBannedFromRoom(roomName, userId)`: Checks if user is currently banned
- `parseBanDuration(duration)`: Converts duration strings to milliseconds

### 6. Database Integrity
- SQLite foreign keys enabled for proper cascade delete
- PostgreSQL support for all tables and operations
- Dual database support maintained (SQLite fallback)

## Testing

### Test Suite: `test:room-management`
Comprehensive test coverage including:
1. Room creation with owner assignment
2. User promotion to admin
3. User role changes (admin to helper)
4. Time-limited bans (5-minute duration)
5. Active ban detection
6. Permanent bans
7. User unbanning
7.5. Admin ban duration restriction (7-day limit verification)
7.6. Owner long-duration ban capability (30-day verification)
8. Room member listing with role ordering
9. Room renaming with foreign key handling
10. Cascade delete verification

All tests pass successfully.

## Migration
- Migration file: `20260130_add_room_management.sql`
- Auto-applied on server startup
- Safe for existing installations (tables created with IF NOT EXISTS)

## Usage

### For Room Owners
```javascript
// Rename room
socket.emit('room:rename', { roomName: 'oldname', newName: 'newname' }, (response) => {
  if (response.ok) console.log('Room renamed');
});

// Promote user to admin
socket.emit('room:promote', { roomName: 'myroom', userId: 123, role: 'admin' }, (response) => {
  if (response.ok) console.log('User promoted');
});

// Demote user
socket.emit('room:demote', { roomName: 'myroom', userId: 123 }, (response) => {
  if (response.ok) console.log('User demoted');
});
```

### For Room Admins and Owners
```javascript
// Ban user for 24 hours
socket.emit('room:ban', { 
  roomName: 'myroom', 
  userId: 456, 
  duration: '24h',
  reason: 'Spam'
}, (response) => {
  if (response.ok) console.log('User banned until', new Date(response.expiresAt));
});

// Permanent ban
socket.emit('room:ban', { 
  roomName: 'myroom', 
  userId: 456, 
  duration: 'forever',
  reason: 'Repeated violations'
}, (response) => {
  if (response.ok) console.log('User permanently banned');
});

// Unban user
socket.emit('room:unban', { roomName: 'myroom', userId: 456 }, (response) => {
  if (response.ok) console.log('User unbanned');
});

// View room bans
socket.emit('room:bans', { roomName: 'myroom' }, (response) => {
  if (response.ok) {
    response.bans.forEach(ban => {
      console.log(`${ban.username}: ${ban.reason} (by ${ban.banned_by})`);
    });
  }
});
```

### For All Users
```javascript
// View room members and their roles
socket.emit('room:members', { roomName: 'myroom' }, (response) => {
  if (response.ok) {
    response.members.forEach(member => {
      console.log(`${member.username}: ${member.role}`);
    });
  }
});
```

## Notes
- Room categorization and creation are already persisted in the database (existing functionality)
- User-created rooms via `/createroom` command now automatically assign ownership
- Ban durations are stored as Unix timestamps (milliseconds since epoch)
- Permanent bans have `expires_at` set to NULL
- Room renaming is handled carefully to maintain foreign key integrity
- All socket events use acknowledgment callbacks for response handling
