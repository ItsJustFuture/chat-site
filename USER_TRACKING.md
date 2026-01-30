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

⚠️ **IMPORTANT SECURITY WARNING**: MAC address tracking has significant limitations and security issues:

1. **Browser Restriction**: Web browsers cannot access MAC addresses due to security restrictions. This feature only works with custom desktop or mobile applications.

2. **Trivial to Spoof**: MAC addresses are sent in HTTP headers and can be easily changed by any client. An attacker can:
   - Bypass MAC-based bans by changing the header value
   - Frame innocent users by spoofing their MAC address
   - Create false positive linked account detections

3. **No Real Security**: Do not rely on MAC addresses for security decisions. They should only be used as supplementary information alongside other moderation factors.

If you still want to implement MAC address tracking (understanding the limitations above):

1. Obtain the MAC address on the client (may require user permission or native APIs)
2. Send it in the socket handshake headers:

```javascript
const socket = io({
  extraHeaders: {
    'x-client-mac': 'aa:bb:cc:dd:ee:ff'  // User's MAC address (easily spoofed!)
  }
});
```

**Recommendation**: Consider removing MAC address tracking entirely, or use it only for informational purposes with clear warnings to moderators about its unreliability.

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
2. **MAC Addresses**: 
   - ⚠️ **IMPORTANT**: MAC addresses are client-provided via HTTP headers and are **trivially spoofable**
   - Any client can send any MAC address they want in the header
   - Should **NOT** be relied upon as the primary or sole factor for moderation decisions
   - Useful only as supplementary data in conjunction with other factors
   - Only works with custom clients (not browser-based applications)
3. **Address Spoofing**: Both IP and MAC addresses can potentially be spoofed, but IPs are harder
4. **VPNs/Proxies**: Users on VPNs may share IP addresses with unrelated users
5. **NAT**: Multiple users behind the same router share an IP address
6. **Collateral Bans**: Banning all addresses of a user may inadvertently affect:
   - Family members or roommates sharing the same IP
   - Users on the same VPN service
   - Users on shared/public networks (coffee shops, libraries, etc.)
   
**Recommendation**: Use address-based bans carefully. Consider whether to ban addresses only for serious offenses, and provide a clear appeal process for false positives.

## Future Enhancements

Potential improvements to consider:

- Automatic alerts when linked accounts are detected
- Confidence scoring for linked account detection
- Time-based correlation (accounts active at the same times)
- Browser fingerprinting for additional tracking
- Automatic action on linked accounts (e.g., ban all linked accounts)
