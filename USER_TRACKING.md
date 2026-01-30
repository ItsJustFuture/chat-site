# User Tracking and Linked Accounts

This document describes the user tracking and linked accounts detection system implemented for moderation purposes.

## Overview

The system tracks every unique MAC address and IP address that users connect from. This information is used for:
1. Enhanced moderation (banning all devices used by a banned user)
2. Detecting linked accounts (alternate accounts using the same IP/MAC)
3. Providing moderators with visibility into user connections

## Features

### 1. Address Tracking

Every time a user connects to the chat:
- Their **IP address** is automatically tracked
- Their **MAC address** is tracked (if sent by the client via `x-client-mac` or `x-mac-address` header)
- Connection history including:
  - First seen timestamp
  - Last seen timestamp
  - Total connection count

### 2. User ID

Every user has a unique User ID (the `id` field in the database) that can be used for moderation actions. This ID is persistent and never changes for a user.

### 3. Enhanced Ban/Kick System

When a user is banned or kicked:
- All IP addresses associated with that user are banned
- All MAC addresses associated with that user are banned
- Future connection attempts from those addresses are automatically blocked
- For kicks, the address ban expires when the kick expires
- For bans, the address ban is permanent (unless the ban has an expiration time)

### 4. Linked Accounts Detection

Moderators, Admins, Co-owners, and the Owner can view linked accounts for any user. Accounts are considered "linked" if they share:
- The same IP address, OR
- The same MAC address

## Usage

### For Moderators/Admins

#### Viewing Linked Accounts

To view linked accounts for a user, emit a socket event:

```javascript
socket.emit("mod get linked accounts", { username: "targetUser" }, (response) => {
  if (response.ok) {
    console.log("Target User ID:", response.targetUserId);
    console.log("Target Username:", response.targetUsername);
    console.log("Linked Users:", response.linkedUsers);
    
    // Each linked user contains:
    // - userId: User's ID
    // - username: User's username
    // - role: User's role
    // - addresses: Array of shared addresses
    //   - type: "ip" or "mac"
    //   - value: The address value
    //   - lastSeen: Last connection timestamp
  }
});
```

#### Banning/Kicking Users

The existing ban and kick commands automatically ban all associated addresses:

```javascript
// Ban (requires Admin role)
socket.emit("mod ban", {
  username: "targetUser",
  minutes: 0,  // 0 = permanent, or specify duration
  reason: "Reason for ban",
  autoClear: false  // Set to true to also clear messages
});

// Kick (requires Moderator role)
socket.emit("mod kick", {
  username: "targetUser",
  durationSeconds: 300,  // Default: 5 minutes
  reason: "Reason for kick",
  autoClear: false  // Set to true to also clear messages
});
```

### For Developers

#### Client-Side MAC Address Tracking

To enable MAC address tracking, the client should send the MAC address in a header when establishing the socket connection. This can be done by:

1. Obtaining the MAC address on the client (may require user permission or browser APIs)
2. Sending it in the socket handshake headers:

```javascript
const socket = io({
  extraHeaders: {
    'x-client-mac': 'aa:bb:cc:dd:ee:ff'  // User's MAC address
  }
});
```

**Note:** Browser-based clients typically cannot access MAC addresses directly due to security restrictions. This feature is more suitable for:
- Desktop applications
- Mobile apps
- Custom clients with appropriate permissions

## Database Schema

### user_addresses Table

Stores all addresses used by each user.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key to users table |
| address_type | TEXT | "ip" or "mac" |
| address_value | TEXT | The IP or MAC address |
| first_seen | INTEGER | Timestamp of first connection |
| last_seen | INTEGER | Timestamp of last connection |
| connection_count | INTEGER | Number of connections from this address |

### address_bans Table

Stores banned IP and MAC addresses.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| address_type | TEXT | "ip" or "mac" |
| address_value | TEXT | The banned IP or MAC address |
| reason | TEXT | Reason for the ban |
| banned_by_user_id | INTEGER | User ID of the moderator who issued the ban |
| banned_by_username | TEXT | Username of the moderator |
| expires_at | INTEGER | Expiration timestamp (null = permanent) |
| created_at | INTEGER | Timestamp when ban was created |

## Privacy Considerations

- Address tracking is for moderation purposes only
- Addresses are not visible to regular users
- Only staff members (Moderator+) can view linked accounts
- Address data should be handled according to your privacy policy
- Consider implementing data retention policies
- Users should be informed about tracking in your Terms of Service

## Security Notes

1. **IP Addresses**: Always tracked automatically from socket connections
2. **MAC Addresses**: Only tracked if sent by the client (requires client support)
3. **Address Spoofing**: Be aware that both IP and MAC addresses can potentially be spoofed
4. **VPNs/Proxies**: Users on VPNs may share IP addresses with unrelated users
5. **NAT**: Multiple users behind the same router share an IP address

## Future Enhancements

Potential improvements to consider:

- Automatic alerts when linked accounts are detected
- Confidence scoring for linked account detection
- Time-based correlation (accounts active at the same times)
- Browser fingerprinting for additional tracking
- Automatic action on linked accounts (e.g., ban all linked accounts)
