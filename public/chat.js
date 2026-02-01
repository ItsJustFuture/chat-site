/**
 * Chat Client - Main application logic
 * Handles all chat interactions after app.js bootstrap completes
 */

(function() {
  'use strict';

  console.log('[chat.js] Loading chat client...');

  // ===== Global State =====
  let socket = null;
  let currentRoom = 'main';
  let currentUser = null;
  let isInitialized = false;
  let globalListenersAttached = false; // Track global listeners to prevent duplicates

  // ===== Wait for app:ready before initializing =====
  async function waitAndInit() {
    console.log('[chat.js] Waiting for app:ready...');
    
    // Ensure waitForAppReady is available
    if (typeof window.waitForAppReady !== 'function') {
      console.error('[chat.js] FATAL: window.waitForAppReady not initialized by app.js - runtime initialization error');
      return;
    }

    try {
      const appState = await window.waitForAppReady();
      console.log('[chat.js] app:ready received');
      
      // Use the globally initialized socket
      socket = appState.socket || window.socket;
      currentUser = appState.currentUser || window.currentUser;
      currentRoom = appState.currentRoom || window.currentRoom;

      // Socket might not be available yet if user just logged in
      // Listen for additional app:ready events in case socket gets initialized later
      if (!socket) {
        console.log('[chat.js] Socket not yet available, waiting for it...');
        window.addEventListener('app:ready', (event) => {
          if (event.detail.socket && !socket) {
            console.log('[chat.js] Socket now available from re-dispatched app:ready');
            socket = event.detail.socket;
            currentUser = event.detail.currentUser || window.currentUser;
            setupSocketListeners();
          }
        });
      } else {
        console.log('[chat.js] Using global socket:', socket.id);
        setupSocketListeners();
      }
    } catch (error) {
      console.error('[chat.js] Failed to wait for app:ready:', error);
    }
  }

  // ===== Socket Event Listeners =====
  function setupSocketListeners() {
    if (!socket) {
      console.error('[chat.js] Cannot setup listeners: socket is null');
      return;
    }

    console.log('[chat.js] Setting up socket event listeners...');

    // Send client hello with browser info
    socket.emit('client:hello', {
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      locale: navigator.language,
      platform: navigator.platform
    });

    // Auto-join main room
    socket.emit('join room', { room: currentRoom, status: 'Online' });

    // Handle disconnect
    socket.on('disconnect', () => {
      console.log('[chat.js] Socket disconnected');
    });

    socket.on('error', (error) => {
      console.error('[chat.js] Socket error:', error);
    });

    // Handle restriction status (kicked/banned)
    socket.on('restriction:status', (data) => {
      console.log('[chat.js] Restriction status:', data);
      // The auth system should handle this
    });

    // Handle user data update (includes role info)
    socket.on('user:data', (data) => {
      console.log('[chat.js] User data received:', data);
      if (data) {
        currentUser = data;
        window.currentUser = data;
        updateUIBasedOnRole(data.role);
        updateBottomPanel(data);
      }
    });

    // Also listen for user:data event from app.js (dispatched on server-ready)
    window.addEventListener('user:data', (event) => {
      const userData = event.detail?.user;
      if (userData) {
        console.log('[chat.js] User data from window event:', userData);
        currentUser = userData;
        window.currentUser = userData;
        updateUIBasedOnRole(userData.role);
        updateBottomPanel(userData);
      }
    });

    // Handle chat messages
    socket.on('chat message', (data) => {
      console.log('[chat.js] Received message:', data);
      // TODO: Display message in UI
    });

    // Handle system messages
    socket.on('system', (data) => {
      console.log('[chat.js] System message:', data);
      // TODO: Display system message
    });

    // Handle room list updates
    socket.on('rooms update', (rooms) => {
      console.log('[chat.js] Rooms updated:', rooms);
      // TODO: Update room list UI
    });

    // Handle user list updates
    socket.on('room users', (data) => {
      console.log('[chat.js] Room users:', data);
      updateMembersList(data);
    });

    console.log('[chat.js] Socket listeners configured ✓');

    // Now attach UI event listeners
    attachEventListeners();
  }

  // ===== UI Update Functions =====
  function updateUIBasedOnRole(role) {
    const roleRank = getRoleRank(role);
    
    // Show admin menu button for Moderator and above
    const membersAdminMenuBtn = document.getElementById('membersAdminMenuBtn');
    if (membersAdminMenuBtn) {
      if (roleRank >= 3) { // Moderator = 3, Admin = 4, Co-owner = 5, Owner = 6
        membersAdminMenuBtn.removeAttribute('hidden');
      } else {
        membersAdminMenuBtn.setAttribute('hidden', '');
      }
    }

    console.log('[chat.js] UI updated for role:', role, 'rank:', roleRank);
  }

  function updateBottomPanel(userData) {
    // Update name panel with user info
    const meName = document.getElementById('meName');
    const meRole = document.getElementById('meRole');
    const meAvatar = document.getElementById('meAvatar');
    
    if (meName) meName.textContent = userData.username || '—';
    if (meRole) meRole.textContent = userData.role || 'User';
    
    if (meAvatar) {
      // Always reset avatar state first to avoid stale text or images
      meAvatar.textContent = '';
      meAvatar.style.backgroundImage = 'none';

      const rawAvatar = userData && userData.avatar != null ? String(userData.avatar).trim() : '';
      let appliedAvatarImage = false;

      if (rawAvatar) {
        // Validate avatar URL to prevent CSS injection
        if (
          rawAvatar.startsWith('http://') ||
          rawAvatar.startsWith('https://') ||
          rawAvatar.startsWith('/')
        ) {
          const safeUrl = rawAvatar.replace(/"/g, '%22');
          meAvatar.style.backgroundImage = `url("${safeUrl}")`;
          appliedAvatarImage = true;
        }
      }

      if (!appliedAvatarImage) {
        // Use default avatar or initials when there is no valid avatar image
        const initials = (userData.username || '?').charAt(0).toUpperCase();
        meAvatar.textContent = initials;
      }
    }

    console.log('[chat.js] Bottom panel updated with user data');
  }

  function updateMembersList(data) {
    const memberList = document.getElementById('memberList');
    if (!memberList) return;

    // Clear existing list efficiently
    while (memberList.firstChild) {
      memberList.removeChild(memberList.firstChild);
    }

    // Sort users by role rank (highest first)
    const users = data.users || [];
    users.sort((a, b) => {
      const rankA = getRoleRank(a.role);
      const rankB = getRoleRank(b.role);
      return rankB - rankA; // Descending order
    });

    // Render members
    users.forEach(user => {
      const memberItem = document.createElement('div');
      memberItem.className = 'memberItem';
      
      const memberAvatar = document.createElement('div');
      memberAvatar.className = 'memberAvatar';
      memberAvatar.textContent = (user.username || '?').charAt(0).toUpperCase();
      
      const memberInfo = document.createElement('div');
      memberInfo.className = 'memberInfo';
      
      const memberName = document.createElement('div');
      memberName.className = 'memberName';
      memberName.textContent = user.username || 'Unknown';
      
      const memberRole = document.createElement('div');
      memberRole.className = 'memberRole';
      memberRole.textContent = user.role || 'User';
      
      memberInfo.appendChild(memberName);
      memberInfo.appendChild(memberRole);
      memberItem.appendChild(memberAvatar);
      memberItem.appendChild(memberInfo);
      memberList.appendChild(memberItem);
    });

    console.log('[chat.js] Members list updated with', users.length, 'members');
  }

  function getRoleRank(role) {
    const ranks = {
      'Guest': 0,
      'User': 1,
      'VIP': 2,
      'Moderator': 3,
      'Admin': 4,
      'Co-owner': 5,
      'Owner': 6
    };
    return ranks[role] || 1;
  }

  // ===== Modal Helper Functions =====
  function openProfileModal(profileData) {
    const modal = document.getElementById('modal');
    if (!modal) return;

    // Populate profile modal with data
    const profileSheetName = document.getElementById('profileSheetName');
    const profileSheetRoleChip = document.getElementById('profileSheetRoleChip');
    const profileMood = document.getElementById('profileMood');
    const infoAge = document.getElementById('infoAge');
    const infoGender = document.getElementById('infoGender');
    const infoRoom = document.getElementById('infoRoom');
    const infoCreated = document.getElementById('infoCreated');
    const infoLastSeen = document.getElementById('infoLastSeen');
    const profileStatus = document.getElementById('profileStatus');
    const bioRender = document.getElementById('bioRender');

    if (profileSheetName) profileSheetName.textContent = profileData.username || '—';
    if (profileSheetRoleChip) profileSheetRoleChip.textContent = profileData.role || 'User';
    if (profileMood) profileMood.textContent = profileData.mood || '';
    if (infoAge) infoAge.textContent = profileData.age || '—';
    if (infoGender) infoGender.textContent = profileData.gender || '—';
    if (infoRoom) infoRoom.textContent = profileData.currentRoom || '—';
    if (infoCreated) infoCreated.textContent = profileData.createdAt ? new Date(profileData.createdAt).toLocaleDateString() : '—';
    if (infoLastSeen) infoLastSeen.textContent = profileData.lastSeen ? new Date(profileData.lastSeen).toLocaleDateString() : '—';
    if (profileStatus) profileStatus.textContent = profileData.status || 'Online';
    
    // Bio may contain formatted text from server (already sanitized server-side)
    // For additional safety, we could sanitize again here if needed
    if (bioRender) {
      if (profileData.bio) {
        bioRender.textContent = profileData.bio; // Use textContent for plain text
      } else {
        bioRender.textContent = '(no bio)';
      }
    }

    // Show avatar if exists
    const profileSheetAvatar = document.getElementById('profileSheetAvatar');
    if (profileSheetAvatar && profileData.avatar) {
      // Validate avatar URL to prevent CSS injection
      const avatarUrl = String(profileData.avatar).trim();
      if (avatarUrl.startsWith('http://') || avatarUrl.startsWith('https://') || avatarUrl.startsWith('/')) {
        profileSheetAvatar.style.backgroundImage = `url("${avatarUrl.replace(/"/g, '%22')}")`;
      }
    }

    // Show modal
    modal.removeAttribute('hidden');
    console.log('[chat.js] Profile modal opened with data:', profileData);
  }

  function openCouplesModal(couplesData) {
    const modal = document.getElementById('couplesModal');
    if (!modal) return;

    const modalBody = document.getElementById('couplesModalBody');
    if (!modalBody) return;

    // Clear existing content efficiently
    while (modalBody.firstChild) {
      modalBody.removeChild(modalBody.firstChild);
    }

    // Display couples data
    if (couplesData.active && couplesData.active.length > 0) {
      const link = couplesData.active[0];
      
      const coupleCard = document.createElement('div');
      coupleCard.className = 'coupleCard';
      
      const coupleHeader = document.createElement('div');
      coupleHeader.className = 'coupleCardHeader';
      
      const coupleTitle = document.createElement('div');
      coupleTitle.className = 'coupleCardTitle';
      coupleTitle.textContent = `${link.user1Name || '—'} & ${link.user2Name || '—'}`;
      
      const coupleStatus = document.createElement('div');
      coupleStatus.className = 'coupleCardStatus';
      coupleStatus.textContent = link.status || 'Linked';
      
      coupleHeader.appendChild(coupleTitle);
      coupleHeader.appendChild(coupleStatus);
      
      const coupleBody = document.createElement('div');
      coupleBody.className = 'coupleCardBody';
      
      const startedText = document.createElement('p');
      startedText.textContent = `Started: ${link.createdAt ? new Date(link.createdAt).toLocaleDateString() : '—'}`;
      coupleBody.appendChild(startedText);
      
      coupleCard.appendChild(coupleHeader);
      coupleCard.appendChild(coupleBody);
      modalBody.appendChild(coupleCard);
    } else if (couplesData.pending && couplesData.pending.length > 0) {
      const pendingText = document.createElement('p');
      pendingText.textContent = 'You have pending couple requests.';
      modalBody.appendChild(pendingText);
    } else {
      const emptyText = document.createElement('p');
      emptyText.textContent = 'No active couples links. Use your profile settings to link with a partner.';
      modalBody.appendChild(emptyText);
    }

    // Show modal
    modal.removeAttribute('hidden');
    modal.removeAttribute('aria-hidden');
    console.log('[chat.js] Couples modal opened with data:', couplesData);
  }

  // ===== Button Event Handlers =====
  function attachEventListeners() {
    console.log('[chat.js] Attaching event listeners to buttons...');

    // Send message button
    const sendBtn = document.getElementById('sendBtn');
    const messageInput = document.getElementById('msgInput');
    
    if (sendBtn && messageInput) {
      const sendMessage = () => {
        const text = messageInput.value.trim();
        if (!text) return;

        // Check socket connection before emitting
        if (!socket || !socket.connected) {
          console.warn('[chat.js] Cannot send message: socket not connected');
          return;
        }

        console.log('[chat.js] Sending message:', text);
        socket.emit('chat message', {
          room: currentRoom,
          text: text
        });

        messageInput.value = '';
      };

      sendBtn.addEventListener('click', sendMessage);
      
      // Note: app.js already handles Enter key for message sending
      // We don't need to duplicate that functionality here

      console.log('[chat.js] Message sending configured');
    } else {
      console.warn('[chat.js] Send button or message input not found');
    }

    // Logout button (top bar)
    const logoutTopBtn = document.getElementById('logoutTopBtn');
    if (logoutTopBtn) {
      logoutTopBtn.addEventListener('click', async () => {
        try {
          // Disconnect socket before logout
          if (socket && socket.connected) {
            socket.disconnect();
          }
          await fetch('/logout', { method: 'POST', credentials: 'include' });
          window.location.reload();
        } catch (err) {
          console.error('[chat.js] Logout failed:', err);
        }
      });
      console.log('[chat.js] Logout button configured');
    }

    // Profile button - open own profile modal
    const profileBtn = document.getElementById('profileBtn');
    const profileModal = document.getElementById('modal');
    if (profileBtn && profileModal) {
      profileBtn.addEventListener('click', async () => {
        console.log('[chat.js] Profile button clicked - opening own profile');
        try {
          // Fetch own profile data
          const response = await fetch('/api/profile', { credentials: 'include' });
          if (response.ok) {
            const data = await response.json();
            openProfileModal(data);
          } else {
            console.error('[chat.js] Failed to fetch own profile');
          }
        } catch (err) {
          console.error('[chat.js] Error fetching profile:', err);
        }
      });
      console.log('[chat.js] Profile button configured');
    }

    // Couples button - open couples modal
    const couplesBtn = document.getElementById('couplesBtn');
    const couplesModal = document.getElementById('couplesModal');
    if (couplesBtn && couplesModal) {
      couplesBtn.addEventListener('click', async () => {
        console.log('[chat.js] Couples button clicked - opening couples modal');
        try {
          // Fetch couples data
          const response = await fetch('/api/couples/me', { credentials: 'include' });
          if (response.ok) {
            const data = await response.json();
            openCouplesModal(data);
          } else {
            console.error('[chat.js] Failed to fetch couples data');
          }
        } catch (err) {
          console.error('[chat.js] Error fetching couples data:', err);
        }
      });
      console.log('[chat.js] Couples button configured');
    }

    // Close profile modal button
    const closeModalBtn = document.getElementById('closeModalBtn');
    if (closeModalBtn && profileModal) {
      closeModalBtn.addEventListener('click', () => {
        profileModal.setAttribute('hidden', '');
      });
    }

    // Close couples modal button
    const couplesModalClose = document.getElementById('couplesModalClose');
    if (couplesModalClose && couplesModal) {
      couplesModalClose.addEventListener('click', () => {
        couplesModal.setAttribute('hidden', '');
        couplesModal.setAttribute('aria-hidden', 'true');
      });
    }

    // DM toggle button
    const dmToggleBtn = document.getElementById('dmToggleBtn');
    const dmPanel = document.getElementById('dmPanel');
    if (dmToggleBtn && dmPanel) {
      dmToggleBtn.addEventListener('click', () => {
        console.log('[chat.js] DM toggle clicked');
        dmPanel.classList.toggle('open');
      });
      console.log('[chat.js] DM toggle button configured');
    }

    // DM close button
    const dmCloseBtn = document.getElementById('dmCloseBtn');
    if (dmCloseBtn && dmPanel) {
      dmCloseBtn.addEventListener('click', () => {
        dmPanel.classList.remove('open');
      });
    }

    // Group DM toggle button (opens same DM panel as DM button)
    const groupDmToggleBtn = document.getElementById('groupDmToggleBtn');
    if (groupDmToggleBtn && dmPanel) {
      groupDmToggleBtn.addEventListener('click', () => {
        console.log('[chat.js] Group DM toggle clicked');
        dmPanel.classList.toggle('open');
      });
      console.log('[chat.js] Group DM toggle button configured');
    }

    // Notifications button
    const notificationsBtn = document.getElementById('notificationsBtn');
    const notificationsModal = document.getElementById('notificationsModal');
    if (notificationsBtn && notificationsModal) {
      notificationsBtn.addEventListener('click', () => {
        console.log('[chat.js] Notifications button clicked');
        notificationsModal.removeAttribute('hidden');
      });
      console.log('[chat.js] Notifications button configured');
    }

    // Close notifications
    const notificationsCloseBtn = document.getElementById('notificationsCloseBtn');
    if (notificationsCloseBtn && notificationsModal) {
      notificationsCloseBtn.addEventListener('click', () => {
        notificationsModal.setAttribute('hidden', '');
      });
    }

    // Channels toggle (mobile)
    const openChannelsBtn = document.getElementById('openChannelsBtn');
    const channelsCloseBtn = document.getElementById('channelsCloseBtn');
    const channelsPane = document.getElementById('channelsPane');
    
    if (openChannelsBtn && channelsPane) {
      openChannelsBtn.addEventListener('click', () => {
        channelsPane.classList.add('open');
        console.log('[chat.js] Channels panel opened');
      });
    }
    
    if (channelsCloseBtn && channelsPane) {
      channelsCloseBtn.addEventListener('click', () => {
        channelsPane.classList.remove('open');
        console.log('[chat.js] Channels panel closed');
      });
    }

    // Menu toggle
    const menuToggleBtn = document.getElementById('menuToggleBtn');
    const menuPanel = document.getElementById('menuPanel');
    
    if (menuToggleBtn && menuPanel) {
      menuToggleBtn.addEventListener('click', () => {
        menuPanel.classList.toggle('show');
        console.log('[chat.js] Menu panel toggled');
      });
      console.log('[chat.js] Menu toggle button configured');
    }

    // Members toggle (mobile)
    const openMembersBtn = document.getElementById('openMembersBtn');
    const membersPane = document.getElementById('membersPane');
    if (openMembersBtn && membersPane) {
      openMembersBtn.addEventListener('click', () => {
        console.log('[chat.js] Members button clicked');
        membersPane.classList.toggle('open');
      });
    }

    // Members close button
    const membersCloseBtn = document.getElementById('membersCloseBtn');
    if (membersCloseBtn && membersPane) {
      membersCloseBtn.addEventListener('click', () => {
        membersPane.classList.remove('open');
        console.log('[chat.js] Members panel closed');
      });
    }

    // Admin menu button (for admins/mods/owners)
    const membersAdminMenuBtn = document.getElementById('membersAdminMenuBtn');
    const membersAdminMenu = document.getElementById('membersAdminMenu');
    if (membersAdminMenuBtn && membersAdminMenu) {
      membersAdminMenuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isHidden = membersAdminMenu.hasAttribute('hidden');
        if (isHidden) {
          membersAdminMenu.removeAttribute('hidden');
          membersAdminMenuBtn.setAttribute('aria-expanded', 'true');
        } else {
          membersAdminMenu.setAttribute('hidden', '');
          membersAdminMenuBtn.setAttribute('aria-expanded', 'false');
        }
        console.log('[chat.js] Admin menu toggled');
      });
      console.log('[chat.js] Admin menu button configured');

      // Close admin menu when clicking outside (only attach once)
      if (!globalListenersAttached) {
        document.addEventListener('click', (e) => {
          const membersAdminMenu = document.getElementById('membersAdminMenu');
          const membersAdminMenuBtn = document.getElementById('membersAdminMenuBtn');
          if (membersAdminMenu && membersAdminMenuBtn && 
              !membersAdminMenu.contains(e.target) && e.target !== membersAdminMenuBtn) {
            membersAdminMenu.setAttribute('hidden', '');
            membersAdminMenuBtn.setAttribute('aria-expanded', 'false');
          }
        });
      }
    }

    // Admin menu items
    const adminMenuAppealsBtn = document.getElementById('adminMenuAppealsBtn');
    if (adminMenuAppealsBtn) {
      adminMenuAppealsBtn.addEventListener('click', () => {
        console.log('[chat.js] Admin appeals button clicked');
        // TODO: Open appeals panel
      });
    }

    const adminMenuReferralsBtn = document.getElementById('adminMenuReferralsBtn');
    if (adminMenuReferralsBtn) {
      adminMenuReferralsBtn.addEventListener('click', () => {
        console.log('[chat.js] Admin referrals button clicked');
        // TODO: Open referrals panel
      });
    }

    const adminMenuCasesBtn = document.getElementById('adminMenuCasesBtn');
    if (adminMenuCasesBtn) {
      adminMenuCasesBtn.addEventListener('click', () => {
        console.log('[chat.js] Admin cases button clicked');
        // TODO: Open cases panel
      });
    }

    const adminMenuRoleDebugBtn = document.getElementById('adminMenuRoleDebugBtn');
    if (adminMenuRoleDebugBtn) {
      adminMenuRoleDebugBtn.addEventListener('click', () => {
        console.log('[chat.js] Admin role debug button clicked');
        // TODO: Open role debug panel
      });
    }

    const adminMenuFeatureFlagsBtn = document.getElementById('adminMenuFeatureFlagsBtn');
    if (adminMenuFeatureFlagsBtn) {
      adminMenuFeatureFlagsBtn.addEventListener('click', () => {
        console.log('[chat.js] Admin feature flags button clicked');
        // TODO: Open feature flags panel
      });
    }

    const adminMenuSessionsBtn = document.getElementById('adminMenuSessionsBtn');
    if (adminMenuSessionsBtn) {
      adminMenuSessionsBtn.addEventListener('click', () => {
        console.log('[chat.js] Admin sessions button clicked');
        // TODO: Open sessions panel
      });
    }

    // Chess button
    const roomChessBtn = document.getElementById('roomChessBtn');
    const chessModal = document.getElementById('chessModal');
    if (roomChessBtn && chessModal) {
      roomChessBtn.addEventListener('click', () => {
        console.log('[chat.js] Chess button clicked');
        chessModal.removeAttribute('hidden');
      });
      console.log('[chat.js] Chess button configured');
    }

    // Chess close button
    const chessCloseBtn = document.getElementById('chessCloseBtn');
    if (chessCloseBtn && chessModal) {
      chessCloseBtn.addEventListener('click', () => {
        chessModal.setAttribute('hidden', '');
      });
    }

    // Media button (upload)
    const mediaBtn = document.getElementById('mediaBtn');
    const mediaMenu = document.getElementById('mediaMenu');
    if (mediaBtn && mediaMenu) {
      mediaBtn.addEventListener('click', () => {
        console.log('[chat.js] Media button clicked');
        mediaMenu.toggleAttribute('hidden');
      });
      console.log('[chat.js] Media button configured');
    }

    // Manage rooms button
    const manageRoomsBtn = document.getElementById('manageRoomsBtn');
    const roomActionsMenu = document.getElementById('roomActionsMenu');
    if (manageRoomsBtn && roomActionsMenu) {
      manageRoomsBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isHidden = roomActionsMenu.hasAttribute('hidden');
        if (isHidden) {
          roomActionsMenu.removeAttribute('hidden');
        } else {
          roomActionsMenu.setAttribute('hidden', '');
        }
        console.log('[chat.js] Manage rooms menu toggled');
      });
      console.log('[chat.js] Manage rooms button configured');

      // Close room actions menu when clicking outside (only attach once)
      if (!globalListenersAttached) {
        document.addEventListener('click', (e) => {
          const roomActionsMenu = document.getElementById('roomActionsMenu');
          const manageRoomsBtn = document.getElementById('manageRoomsBtn');
          if (roomActionsMenu && manageRoomsBtn &&
              !roomActionsMenu.contains(e.target) && e.target !== manageRoomsBtn) {
            roomActionsMenu.setAttribute('hidden', '');
          }
        });
        globalListenersAttached = true; // Mark that global listeners are now attached
      }
    }

    // Room action buttons
    const roomActionButtons = document.querySelectorAll('[data-room-action]');
    roomActionButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const action = btn.getAttribute('data-room-action');
        console.log('[chat.js] Room action clicked:', action);
        
        // Hide the menu after clicking
        if (roomActionsMenu) {
          roomActionsMenu.setAttribute('hidden', '');
        }

        // Handle different room actions
        switch (action) {
          case 'add-category':
            console.log('[chat.js] Add category - TODO');
            // TODO: Show add category dialog
            break;
          case 'add-room':
            console.log('[chat.js] Add room - TODO');
            // TODO: Show add room dialog
            break;
          case 'add-vip-room':
            console.log('[chat.js] Add VIP room - TODO');
            // TODO: Show add VIP room dialog
            break;
          case 'manage-rooms':
            console.log('[chat.js] Manage rooms - TODO');
            // TODO: Show room management panel
            break;
          default:
            console.log('[chat.js] Unknown room action:', action);
        }
      });
    });
    if (roomActionButtons.length > 0) {
      console.log('[chat.js] Room action buttons configured:', roomActionButtons.length);
    }

    console.log('[chat.js] Event listeners attached successfully');
  }

  // ===== Initialization =====
  function initialize() {
    // Check at the very beginning to prevent race conditions
    if (isInitialized) {
      console.log('[chat.js] Already initialized');
      return;
    }

    // Set immediately to prevent race conditions with multiple initialization calls
    isInitialized = true;

    console.log('[chat.js] Chat UI initialized');
    // Note: attachEventListeners is called from setupSocketListeners after socket is ready
  }

  // ===== Public API =====
  window.chatApp = {
    initialize,
    isInitialized: () => isInitialized
  };

  // Start waiting for app:ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', waitAndInit);
  } else {
    waitAndInit();
  }

  console.log('[chat.js] Chat client loaded, waiting for bootstrap...');
})();
