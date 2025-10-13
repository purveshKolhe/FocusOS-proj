// study_room.js

let socket;
let currentRoom;
let timerInterval;
let currentUser; // This will be the username, used as userId for notifications
let currentUsername = ''; // Kept for chat display name logic
let currentRoomKey = '';
let hasPromptedForName = false;
let studyRoomScriptInitialized = false; // Global guard for the script's DOMContentLoaded logic
let agoraClient = null;
let localVideoTrack = null;
let remoteUsers = {};
let agoraUid = null;
let agoraAppId = null;
let agoraUidToNameMap = {};

// Combined DOMContentLoaded event listener
document.addEventListener('DOMContentLoaded', async function() {
    if (studyRoomScriptInitialized) {
        console.log('[Study Room] DOMContentLoaded fired again, but script already initialized. Skipping.');
        return;
    }
    studyRoomScriptInitialized = true;
    console.log('[Study Room] DOMContentLoaded fired, initializing script...');

    // Attempt to remove conflicting jQuery event handlers from script.js
    if (typeof $ !== 'undefined') {
        try {
            // For #focus-mode button (direct handler in script.js)
            $('#focus-mode').off('click');
            console.log('[Study Room] jQuery click handler for #focus-mode potentially removed by study_room.js');

            // For #exit-focus button (delegated handler in script.js)
            $(document).off('click', '#exit-focus');
            console.log('[Study Room] jQuery delegated click handler for #exit-focus potentially removed by study_room.js');

        } catch (e) {
            console.warn('Error trying to remove jQuery handlers in study_room.js:', e);
        }
    }

    // Initialize Socket.IO connection
    // Ensure socket is initialized only once
    if (!socket) {
        socket = io();
    }
    currentRoom = window.location.pathname.split('/').pop();
    currentRoomKey = 'hasPromptedForName_' + currentRoom;
    hasPromptedForName = sessionStorage.getItem(currentRoomKey) === 'true';

    try {
        console.log("[Study Room] Waiting for Firebase Auth to be ready...");
        const firebaseUser = await window.firebaseAuthReady; // Wait for Firebase Auth
        console.log("[Study Room] Firebase Auth ready. Firebase User:", firebaseUser ? firebaseUser.uid : "null");

        const response = await fetch('/api/user_data');
        const data = await response.json();
        
        if (data.error) {
            console.error("Error fetching user data:", data.error);
            currentUser = 'UnknownUser_API_Error'; // Fallback for debugging
            currentUsername = 'Anonymous_API_Error'; // Fallback for debugging
            if(typeof addNotification === 'function') {
                showToastNotification("User Data Error: Could not load your user details.", "error");
            }
        } else {
            currentUser = data.username; // This should be Firebase UID
            currentUsername = data.display_username || data.username || 'Anonymous'; // Display name
        }

        console.log(`[Study Room] API UserID: ${currentUser}, Display Name: ${currentUsername}`);

        const setupRoomFeatures = (fbUser, apiUserId, apiDisplayName) => {
            // This function will be called once Firebase auth state is known.
            if (fbUser && fbUser.uid === apiUserId) {
                console.log(`[Study Room] Firebase Auth Confirmed: UID ${fbUser.uid} matches API UserID ${apiUserId}. Initializing notifications.`);
            if (typeof initializeGlobalNotificationSystem === 'function') {
                    initializeGlobalNotificationSystem(fbUser.uid); // Initialize with actual Firebase UID

                // Add a welcome notification specific to the study room, only once per session
                if (!sessionStorage.getItem('studyRoomWelcomeNotificationSent_' + currentRoom)) {
                    const roomNameElement = document.querySelector('.room-name-center');
                    const roomName = roomNameElement ? roomNameElement.textContent.trim() : 'the study room';
                    if (typeof addNotification === 'function') {
                            addNotification('Study Room Joined', `Welcome to ${roomName}, ${apiDisplayName}!`, 'info');
                    }
                    sessionStorage.setItem('studyRoomWelcomeNotificationSent_' + currentRoom, 'true');
                }
            } else {
                    console.error("[Study Room] initializeGlobalNotificationSystem is not defined. CRITICAL: Ensure notifications.js is loaded BEFORE study_room.js.");
                }
            } else {
                if (!fbUser) {
                    console.warn(`[Study Room] Firebase user is NULL when trying to set up room for API UserID: ${apiUserId}. Notifications likely disabled.`);
                    if (typeof showToastNotification === 'function') {
                        showToastNotification("Client not signed into Firebase. Notifications may not work. Try re-logging in.", "error");
                    } else if (typeof addNotification === 'function') {
                        addNotification("Firebase Auth Issue", "Client not signed into Firebase. Notifications may not work. Try re-logging in.", "error");
                    }
                } else { // fbUser.uid !== apiUserId
                    console.error(`[Study Room] CRITICAL UID MISMATCH: API UserID is ${apiUserId}, but Firebase Auth UID is ${fbUser.uid}.`);
                    if (typeof showToastNotification === 'function') {
                        showToastNotification("User identity mismatch. Please re-login immediately.", "error");
                    } else if (typeof addNotification === 'function') {
                        addNotification("Critical Auth Mismatch", "User identity mismatch. Please re-login immediately.", "error");
                    }
                }
            }

            // Emit join_room, using apiUserId (Firebase UID) and apiDisplayName
        socket.emit('join_room', {
            room: currentRoom,
                user_id: apiUserId,      // Send Firebase UID as user_id
                display_name: apiDisplayName // Send display name separately
        });

            // Initialize other socket event listeners that might have been deferred
        // Wait for socket connection to be established
        socket.on('connect', () => {
            console.log('[Socket] Connected to server for study room:', currentRoom);
            fetchAndRenderParticipants();
        });

        socket.on('status', function(data) {
            console.log('[Socket] Received status:', data);
            fetchAndRenderParticipants(); // Update participants on status changes (join/leave)
            const chatMessages = document.getElementById('chat-messages');
            if (chatMessages) {
                const msgDiv = document.createElement('div');
                msgDiv.className = 'chat-message text-gray-400 text-center my-2';
                msgDiv.textContent = data.msg;
                chatMessages.appendChild(msgDiv);
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }
                // Use global notification for room updates (this relies on addNotification working)
                if (apiUserId && !apiUserId.startsWith('UnknownUser_') && fbUser && fbUser.uid === apiUserId) { // Only if notifications are expected to work
            if (typeof addNotification === 'function') {
                addNotification('Room Update', data.msg, 'info');
                    }
                } else {
                     if (typeof showToastNotification === 'function') {
                        showToastNotification(`Room Update: ${data.msg}`, 'info'); // Fallback toast
                    }
                }
            });
        };

        if (!currentUser || currentUser.startsWith('UnknownUser_')) {
            console.error("[Study Room] User ID from API is invalid or missing:", currentUser, ". Cannot proceed with Firebase-dependent features reliably.");
             if (typeof showToastNotification === 'function') {
                showToastNotification("User Data Error: Could not load your user details for the room.", "error");
            } else if(typeof addNotification === 'function') { // Fallback, though addNotification might fail
                addNotification("User Data Error", "Could not load your user details for the room. Some features might be limited.", "error");
            }
            // Still emit join_room with a fallback username
            socket.emit('join_room', {
                room: currentRoom,
                username: currentUsername || 'ErrorUser'
            });
             // Setup basic socket listeners even if full auth fails
            socket.on('connect', () => {
                console.log('[Socket] Connected to server for study room (fallback):', currentRoom);
                 fetchAndRenderParticipants();
            });
            socket.on('status', function(data) {
                console.log('[Socket] Received status (fallback):', data);
                fetchAndRenderParticipants();
                const chatMessages = document.getElementById('chat-messages');
                if (chatMessages) { /* ... add simple status message ... */ }
                if (typeof showToastNotification === 'function') {
                    showToastNotification(`Room Update: ${data.msg}`, 'info');
                }
            });
        } else {
            // DEPRECATED: Firebase-dependent setup is now called directly after awaiting firebaseAuthReady
            // const unsubscribeAuth = firebase.auth().onAuthStateChanged(user => {
            //     unsubscribeAuth(); // Call only once to get initial state
            //     console.log("[Study Room] Firebase onAuthStateChanged event. User:", user ? user.uid : "null");
            //     setupRoomFeatures(user); // Pass the Firebase user object
            // });
        }

        // setupRoomFeatures will now directly use the firebaseUser obtained from the promise
        setupRoomFeatures(firebaseUser, currentUser, currentUsername);

        // Initialize Video Call
        initVideoCall();

    } catch (error) {
        console.error('Error during initial setup in study_room.js (after auth wait):', error);
        currentUser = 'UnknownUser_Catch_Error'; 
        currentUsername = 'Anonymous_Catch_Error'; 
        if (typeof showToastNotification === 'function') {
            showToastNotification("Study Room Setup Error. Some features may be affected.", "error");
        } else if(typeof addNotification === 'function'){
            addNotification("Study Room Setup Error", "Could not fully initialize the study room. Some features may be affected.", "error");
        }
        // Fallback join if socket is available
        if (socket && currentRoom) {
             socket.emit('join_room', {
                room: currentRoom,
                username: currentUsername
            });
        }
    }

    // Add name change functionality to chat tab
    const chatTab = document.querySelector('[data-target="chat-panel"]');
    if (chatTab) {
        chatTab.addEventListener('click', function() {
            if (!hasPromptedForName) {
                const newName = prompt('Enter your display name for this room:', currentUsername);
                if (newName && newName.trim() && newName.trim() !== currentUsername) {
                    const oldName = currentUsername;
                    currentUsername = newName.trim();
                    // Note: currentUser (the ID for notifications) should NOT change here.
                    // It's tied to the logged-in user. We're only changing the display name for chat.
                    
                    socket.emit('send_room_message', {
                        room: currentRoom,
                        username: 'System', // System message for name change
                        message: `${oldName} changed their name to ${currentUsername}`
                    });
                    // Potentially update display name in participants list if it's shown
                    fetchAndRenderParticipants(); 
                }
                hasPromptedForName = true; // Mark as prompted for this room
                sessionStorage.setItem(currentRoomKey, 'true');
            }
        });
    }

    // Chat input handlers using jQuery .off().on() for robustness
    if (typeof $ !== 'undefined') {
        const $chatInput = $('#chat-input');
        const $sendMessageBtn = $('#send-message');

        if ($sendMessageBtn.length && $chatInput.length) {
            console.log('[Study Room Chat] Found chat input and send button. Preparing listeners.');
            const sendRoomChatMessage = () => {
                const message = $chatInput.val().trim();
                if (message) {
                    console.log(`[Study Room Chat] Attempting to send message: "${message}". Current username: ${currentUsername}`);
                    socket.emit('send_room_message', {
                        room: currentRoom,
                        username: currentUsername, // Send with current display name
                        message: message
                    });
                    console.log('[Study Room Chat] Message emitted via socket.');
                    $chatInput.val(''); // Clear the input field
                } else {
                    console.log('[Study Room Chat] Send attempt: Message is empty.');
                }
            };

            // Remove any existing listeners and attach the new one
            $sendMessageBtn.off('click').on('click', function() {
                console.log('[Study Room Chat] Send button clicked.');
                sendRoomChatMessage();
            });

            $chatInput.off('keypress').on('keypress', function(e) {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    console.log('[Study Room Chat] Enter key pressed in chat input.');
                    sendRoomChatMessage();
                }
            });
            console.log('[Study Room Chat] jQuery chat send listeners attached.');
        } else {
            console.warn('[Study Room Chat] Chat input or send button not found for jQuery listeners.');
        }
    } else {
        console.error('[Study Room Chat] jQuery is not defined. Chat send functionality might be impaired.');
        // Fallback to vanilla JS if necessary, though this path should ideally not be hit if base.html loads jQuery
        const sendMessageBtn = document.getElementById('send-message');
        const chatInput = document.getElementById('chat-input');
        if (sendMessageBtn && chatInput) {
            const sendRoomChatMessageVanilla = () => {
                const message = chatInput.value.trim();
                if (message) {
                    socket.emit('send_room_message', {
                        room: currentRoom,
                        username: currentUsername,
                        message: message
                    });
                    chatInput.value = '';
                }
            };
            // To prevent vanilla duplicates if this block runs unexpectedly multiple times,
            // this simple vanilla version doesn't have an .off() equivalent without more complex listener management.
            // The primary solution relies on jQuery .off().on().
            sendMessageBtn.addEventListener('click', sendRoomChatMessageVanilla);
            chatInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendRoomChatMessageVanilla();
                }
            });
             console.log('[Study Room] Vanilla JS chat send listeners attached as fallback.');
        }
    }

    // Room chat event handlers
    // Use .off().on() to prevent duplicate handler attachments
    socket.off('receive_room_message').on('receive_room_message', function(data) {
        const chatMessagesContainer = document.getElementById('chat-messages');
        if (chatMessagesContainer) {
            renderChatMessage(data, currentUsername); // Pass current display name
            chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
        }

        // Notify if message is from another user and not a system message
        if (data.username && data.username.toLowerCase() !== 'system' && data.username !== currentUsername) {
            if (typeof addNotification === 'function') {
                let roomDisplayName = 'this study room'; // Default
                const roomNameElement = document.querySelector('.room-name-center');
                if (roomNameElement) {
                    roomDisplayName = roomNameElement.textContent.trim() || roomDisplayName;
                }
                
                const messagePreview = data.message.length > 40 
                                     ? data.message.substring(0, 37) + '...' 
                                     : data.message;
                
                addNotification(
                    `New message in ${roomDisplayName}`,
                    `${data.username}: "${messagePreview}"`,
                    'info' 
                );
            }
        }
    });

    // Load chat history
    fetch(`/api/room_chat_history/${currentRoom}`)
        .then(res => {
            if (!res.ok) throw new Error(`Failed to load chat history: ${res.statusText}`);
            return res.json();
        })
        .then(messages => {
            const chatMessages = document.getElementById('chat-messages');
            if (chatMessages) {
                chatMessages.innerHTML = ''; // Clear before rendering
                messages.forEach(msg => renderChatMessage(msg, currentUsername)); // Pass current display name
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }
        })
        .catch(error => {
            console.error('Error loading room chat history:', error);
            if(typeof addNotification === 'function') addNotification("Chat Error", "Could not load previous messages.", "warning");
        });

    // Remove any duplicate room_timer_update listeners
    socket.off('room_timer_update');

    // Listen for timer updates (single handler)
    socket.on('room_timer_update', function(data) {
        if (data.room !== currentRoom) return;
        updateStudyRoomTimerDisplay(data.timeLeft);
        updateSessionLabel(data.isWorkSession);
        const startSharedTimer = document.getElementById('start-shared-timer');
        const pauseSharedTimer = document.getElementById('pause-shared-timer');
        if(startSharedTimer && pauseSharedTimer){
            if (data.isRunning) {
                startSharedTimer.classList.add('hidden');
                pauseSharedTimer.classList.remove('hidden');
            } else {
                startSharedTimer.classList.remove('hidden');
                pauseSharedTimer.classList.add('hidden');
                clearInterval(timerInterval);
            }
        }
        if (!timerReady) {
            setTimerControlsEnabled(true);
            timerReady = true;
        }
    });

    // Listen for join error
    socket.on('join_error', function(data) {
        setTimerControlsEnabled(false);
        if (typeof addNotification === 'function') {
            addNotification('Room Join Error', data.message || 'Could not join room.', 'error');
        } else {
            alert('Room Join Error: ' + (data.message || 'Could not join room.'));
        }
    });

    // Timer controls
    const startSharedTimerBtn = document.getElementById('start-shared-timer');
    if(startSharedTimerBtn){
        startSharedTimerBtn.addEventListener('click', function() {
            if (!timerReady) return;
            socket.emit('room_timer_control', {
                room: currentRoom,
                action: 'start',
                user_id: currentUser
            });
            playSound('sound-click');
        });
    }
    const pauseSharedTimerBtn = document.getElementById('pause-shared-timer');
    if(pauseSharedTimerBtn){
        pauseSharedTimerBtn.addEventListener('click', function() {
            if (!timerReady) return;
            socket.emit('room_timer_control', {
                room: currentRoom,
                action: 'pause',
                user_id: currentUser
            });
            playSound('sound-click');
        });
    }
    const resetSharedTimerBtn = document.getElementById('reset-shared-timer');
    if(resetSharedTimerBtn){
        resetSharedTimerBtn.addEventListener('click', function() {
            if (!timerReady) return;
            socket.emit('room_timer_control', {
                room: currentRoom,
                action: 'reset',
                user_id: currentUser
            });
            playSound('sound-click');
        });
    }

    // Duration change handlers
    const sharedWorkDurationInput = document.getElementById('shared-work-duration');
    if(sharedWorkDurationInput){
        sharedWorkDurationInput.addEventListener('change', function() {
            const newWorkDuration = parseInt(this.value);
            const sharedBreakDurationInput = document.getElementById('shared-break-duration');
            const newBreakDuration = sharedBreakDurationInput ? parseInt(sharedBreakDurationInput.value) : null;

            if (!isNaN(newWorkDuration) && newWorkDuration > 0) {
                let payload = {
                    room: currentRoom,
                    action: 'duration_change',
                    workDuration: newWorkDuration,
                    user_id: currentUser
                };
                if (newBreakDuration !== null && !isNaN(newBreakDuration) && newBreakDuration > 0) {
                    payload.breakDuration = newBreakDuration;
                }
                socket.emit('room_timer_control', payload);
                playSound('sound-click'); // Added sound
            }
        });
    }

    const sharedBreakDurationInput = document.getElementById('shared-break-duration');
    if(sharedBreakDurationInput){
        sharedBreakDurationInput.addEventListener('change', function() {
            const newBreakDuration = parseInt(this.value);
            const sharedWorkDurationInput = document.getElementById('shared-work-duration');
            const newWorkDuration = sharedWorkDurationInput ? parseInt(sharedWorkDurationInput.value) : null;

            if (!isNaN(newBreakDuration) && newBreakDuration > 0) {
                 let payload = {
                    room: currentRoom,
                    action: 'duration_change',
                    breakDuration: newBreakDuration,
                    user_id: currentUser
                };
                if (newWorkDuration !== null && !isNaN(newWorkDuration) && newWorkDuration > 0) {
                    payload.workDuration = newWorkDuration;
                }
                socket.emit('room_timer_control', payload);
                playSound('sound-click'); // Added sound
            }
        });
    }

    // Initial timer state fetch
    fetchTimerStateAndSync();

    // Invite modal logic
    const inviteBtn = document.getElementById('invite-btn');
    const inviteModal = document.getElementById('invite-modal');
    const closeInviteModal = document.getElementById('close-invite-modal');
    const copyLinkBtn = document.getElementById('copy-link');

    if (inviteBtn && inviteModal) {
        inviteBtn.addEventListener('click', function() {
            inviteModal.classList.remove('hidden');
            const roomCodeDisplay = document.querySelector('.room-code-display');
            if (roomCodeDisplay) {
                const roomCode = roomCodeDisplay.textContent.trim();
            const roomLink = `${window.location.origin}/room/${roomCode}`;
                const linkDiv = document.getElementById('room-link-to-copy');
            if (linkDiv) linkDiv.textContent = roomLink;
            }
        });
    }
    if (closeInviteModal && inviteModal) {
        closeInviteModal.addEventListener('click', function() {
            inviteModal.classList.add('hidden');
        });
    }
    if (copyLinkBtn) {
        copyLinkBtn.addEventListener('click', function() {
            const linkDiv = document.getElementById('room-link-to-copy');
            const roomLink = linkDiv ? linkDiv.textContent.trim() : '';
            if (roomLink) {
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(roomLink).then(() => {
                        if(typeof addNotification === 'function') addNotification("Invite", "Room link copied to clipboard!", "success");
                    }).catch(() => {
                        fallbackCopyTextToClipboard(roomLink);
                    });
                } else {
                    fallbackCopyTextToClipboard(roomLink);
                }
            } else {
                if(typeof addNotification === 'function') addNotification("Invite", "No link to copy.", "error");
            }
        });
    }

    // Fallback for older browsers
    function fallbackCopyTextToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            if(typeof addNotification === 'function') addNotification("Invite", "Room link copied!", "success");
        } catch (err) {
            if(typeof addNotification === 'function') addNotification("Invite", "Failed to copy link.", "error");
        }
        document.body.removeChild(textArea);
    }

    // Leave button logic
    const leaveRoomBtn = document.getElementById('leave-room');
    if (leaveRoomBtn) {
        leaveRoomBtn.addEventListener('click', function() {
            console.log('[Frontend] Leave room button clicked');
            console.log('[Frontend] Current room:', currentRoom);
            console.log('[Frontend] Current user (UID for leave event):', currentUser); // currentUser is Firebase UID
            
            if (confirm('Are you sure you want to leave the room?')) {
                console.log('[Frontend] User confirmed leaving room');
                // Leave video call first
                leaveVideoCall();
                // Emit leave_room event with user_id (Firebase UID)
                socket.emit('leave_room', { 
                    room: currentRoom, 
                    user_id: currentUser // Send Firebase UID as user_id
                }, (response) => {
                    console.log('[Frontend] Leave room response:', response);
                });
                
                // Redirect to home page
                window.location.href = '/';
            }
        });
    }

    // Load user data and stats
    async function loadUserData() {
        try {
            const response = await fetch('/api/user_data');
            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }
            
            // Update level and XP
            const levelEl = document.getElementById('level');
            const xpEl = document.getElementById('xp');
            const xpNeededEl = document.getElementById('xp-needed');
            const xpProgressEl = document.getElementById('xp-progress');

            if(levelEl) levelEl.textContent = data.progress.level;
            if(xpEl) xpEl.textContent = data.progress.xp;
            if(xpNeededEl && data.progress.level) xpNeededEl.textContent = data.progress.level * 100;
            if(xpProgressEl && data.progress.xp && data.progress.level) xpProgressEl.style.width = `${(data.progress.xp / (data.progress.level * 100)) * 100}%`;
            
            // Update stats
            const totalTimeEl = document.getElementById('total-time');
            const streakEl = document.getElementById('streak');
            const statsTotalTimeEl = document.getElementById('stats-total-time');
            const statsTotalSessionsEl = document.getElementById('stats-total-sessions');

            if(totalTimeEl && data.progress.total_time !== undefined) totalTimeEl.textContent = data.progress.total_time;
            if(streakEl && data.progress.streak !== undefined) streakEl.textContent = data.progress.streak;
            if(statsTotalTimeEl && data.progress.total_time !== undefined) statsTotalTimeEl.textContent = `${data.progress.total_time} min`;
            if(statsTotalSessionsEl && data.progress.sessions !== undefined) statsTotalSessionsEl.textContent = data.progress.sessions;
            
        } catch (error) {
            console.error('Error loading user data:', error);
        }
    }
    loadUserData(); // Load user data on page load

    // Initialize dark mode toggle
    const dayNightToggle = document.getElementById('day-night-toggle');
    if (dayNightToggle) {
    dayNightToggle.addEventListener('change', function() {
        document.body.classList.toggle('night-mode');
    });
    }
    
    // Initialize particles
    if (typeof particlesJS !== 'undefined' && document.getElementById('particles-js')) {
        particlesJS('particles-js', {
            particles: {
                number: { value: 80 },
                color: { value: '#ffffff' },
                shape: { type: 'circle' },
                opacity: { value: 0.5 },
                size: { value: 3 },
                move: { enable: true, speed: 2 }
            }
        });
    }

    // Fetch and render participants list
    async function fetchAndRenderParticipants() {
        try {
            console.log('[Participants] Starting to fetch participants for room:', currentRoom);
            const res = await fetch(`/api/room_participants/${currentRoom}`);
            console.log('[Participants] API response status:', res.status);
            const data = await res.json();
            console.log('[Participants] API response data:', data);
            
            const participantsList = document.getElementById('participants-list');
            if (!participantsList) {
                console.error('[Participants] Error: participants-list element not found in DOM');
                return;
            }
            
            participantsList.innerHTML = ''; // Clear existing participants
            
            if (data.participants && data.participants.length > 0) {
                data.participants.forEach(participant => {
                    const participantDiv = document.createElement('div');
                    participantDiv.className = 'participant flex items-center space-x-3 p-3 bg-gray-800 bg-opacity-60 rounded-lg mb-2';
                    
                    const isHost = data.host_id === participant;
                    const hostLabel = isHost ? '<span class="text-yellow-400 text-sm ml-2">(host)</span>' : '';
                    
                    participantDiv.innerHTML = `
                        <div class="participant-avatar w-10 h-10 rounded-full bg-purple-600 flex items-center justify-center font-bold text-lg">
                            ${participant.substring(0, 2).toUpperCase()}
                        </div>
                        <div class="participant-name text-white">${participant}${hostLabel}</div>
                    `;
                    participantsList.appendChild(participantDiv);
                });
            } else {
                participantsList.innerHTML = '<p class="text-gray-400 text-center">No participants yet</p>';
            }
        } catch (error) {
            console.error('[Participants] Error fetching participants:', error);
        }
    }

    // Always fetch participants on page load
    fetchAndRenderParticipants();

    // Tab navigation: show the correct panel and hide others
    document.querySelectorAll('.nav-tab').forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active from all tabs and panels
            document.querySelectorAll('.nav-tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.content-panel').forEach(panel => panel.classList.remove('active'));
            // Add active to clicked tab and its panel
            btn.classList.add('active');
            const target = btn.getAttribute('data-target');
            const panel = document.getElementById(target);
            if (panel) panel.classList.add('active');
            // Fetch participants if needed
            if (target === 'participants-panel') {
                fetchAndRenderParticipants();
            }
        });
    });

    // Fetch and render chat history
    fetch(`/api/room_chat_history/${currentRoom}`)
        .then(res => res.json())
        .then(messages => {
            const chatMessages = document.getElementById('chat-messages');
            if(chatMessages){
            chatMessages.innerHTML = '';
                 messages.forEach(msg => renderChatMessage(msg, currentUsername));
            chatMessages.scrollTop = chatMessages.scrollHeight;
            }
        });

    window.addEventListener('beforeunload', function() {
        // Leave video call before page unloads
        leaveVideoCall();
        if (socket && currentRoom && currentUser) { // currentUser is Firebase UID
            // For beforeunload, the server relies on the 'disconnect' event primarily.
            // Explicitly emitting 'leave_room' here can be redundant if disconnect is handled robustly,
            // and might not always complete before the tab closes.
            // However, if desired for an immediate attempt:
            // socket.emit('leave_room', { room: currentRoom, user_id: currentUser });
            console.log('[Frontend] beforeunload: User (UID: '+ currentUser +') is leaving room ' + currentRoom + '. Server will handle via disconnect.');
        }
    });

    // Add socket event handlers for room events
    socket.on('room_deleted', function(data) {
        console.log('[Frontend] Room deleted event received:', data);
        if (typeof addNotification === 'function') {
            addNotification('Room Deleted', data.message, 'warning');
        }
        setTimeout(() => {
            window.location.href = '/';
        }, 2000);
    });

    socket.on('room_error', function(data) {
        console.log('[Frontend] Room error event received:', data);
        if (typeof addNotification === 'function') {
            addNotification('Room Error', data.message, 'error');
        }
    });

    // Add handler for disconnect event
    socket.on('disconnect', function() {
        console.log('[Frontend] Socket disconnected');
        // No need to emit leave_room here, server handles disconnect event and cleans up using active_sessions.
        // if (socket && currentRoom && currentUser) { // currentUser is Firebase UID
        //     console.log('[Frontend] Attempting to leave room on disconnect via client emit - redundant if server handles disconnect well');
        //     socket.emit('leave_room', { 
        //         room: currentRoom, 
        //         user_id: currentUser 
        //     });
        // }
    });

    // Rules Modal Logic for Study Room
    const rulesButton = document.getElementById('rules-button');
    const rulesModal = document.getElementById('rules-modal');
    const closeRulesButton = document.getElementById('close-rules');

    if (rulesButton && rulesModal) {
        rulesButton.addEventListener('click', function(event) {
            event.stopImmediatePropagation(); // Attempt to prevent other handlers
            rulesModal.style.display = 'flex';
            rulesModal.classList.remove('hidden');
            playSound('sound-click');
        });
    }
    if (closeRulesButton && rulesModal) {
        closeRulesButton.addEventListener('click', function(event) {
            event.stopImmediatePropagation(); // Attempt to prevent other handlers
            rulesModal.style.display = 'none';
            rulesModal.classList.add('hidden');
            playSound('sound-click');
        });
    }
    if (rulesModal) {
        rulesModal.addEventListener('click', function(event) {
            if (event.target === rulesModal) {
                rulesModal.style.display = 'none';
                rulesModal.classList.add('hidden');
                playSound('sound-click');
            }
        });
    }

    // Focus Mode logic
    const focusModeBtn_study = document.getElementById('focus-mode');
    const focusOverlay_study = document.getElementById('focus-overlay');
    const exitFocusBtn_study = document.getElementById('exit-focus');

    if (focusModeBtn_study && focusOverlay_study) {
        focusModeBtn_study.addEventListener('click', function(event) {
            event.stopImmediatePropagation(); // Prevent conflicting handlers from script.js
            document.body.classList.toggle('focus-mode');
            const isFocus = document.body.classList.contains('focus-mode');
            if (isFocus) {
                focusOverlay_study.classList.remove('hidden');
                focusOverlay_study.style.display = 'flex';
                this.innerHTML = '<i class="fas fa-eye-slash"></i>'; 
                const tooltip = this.querySelector('.tooltiptext');
                if (tooltip) tooltip.textContent = "Exit Focus Mode";
                if (typeof addNotification === 'function') addNotification("Focus mode enabled", "info");
            } else {
                focusOverlay_study.style.display = 'none';
                focusOverlay_study.classList.add('hidden');
                this.innerHTML = '<i class="fas fa-eye"></i>'; 
                const tooltip = this.querySelector('.tooltiptext');
                if (tooltip) tooltip.textContent = "Enter Focus Mode";
                if (typeof addNotification === 'function') addNotification("Focus mode disabled", "info");
            }
            playSound('sound-click');
        });
    }

    if (exitFocusBtn_study && focusOverlay_study) {
        exitFocusBtn_study.addEventListener('click', function(event) {
            event.stopImmediatePropagation(); // Prevent conflicting handlers from script.js
            document.body.classList.remove('focus-mode');
            focusOverlay_study.style.display = 'none';
            focusOverlay_study.classList.add('hidden');
            if (focusModeBtn_study) { 
                focusModeBtn_study.innerHTML = '<i class="fas fa-eye"></i>';
                const tooltip = focusModeBtn_study.querySelector('.tooltiptext');
                if (tooltip) tooltip.textContent = "Enter Focus Mode";
            }
            if (typeof addNotification === 'function') addNotification("Focus mode disabled", "info");
            playSound('sound-click');
        });
    }
    const uploadImageBtn = document.getElementById('upload-image-btn');
    const imageUpload = document.getElementById('image-upload');
    if (uploadImageBtn && imageUpload) {
        const newUploadImageBtn = uploadImageBtn.cloneNode(true);
        if(uploadImageBtn.parentNode) uploadImageBtn.parentNode.replaceChild(newUploadImageBtn, uploadImageBtn);
        newUploadImageBtn.addEventListener('click', () => {
            // Ensure we get the LATEST reference to imageUpload, in case it was also cloned.
            const currentImageUpload = document.getElementById('image-upload');
            if (currentImageUpload) {
                currentImageUpload.click();
            }
        });
    }

    // Add socket event handlers for video call user identities
    socket.on('video_user_identity', function(data) {
        console.log('[Agora] Received user identity:', data);
        agoraUidToNameMap[data.agora_uid] = data.display_name;
        // If a video player for this user already exists but has a placeholder name, update it.
        const usernameSpan = document.getElementById(`username-${data.agora_uid}`);
        if (usernameSpan) {
            usernameSpan.textContent = data.display_name;
        }
    });

    socket.on('existing_video_users', function(data) {
        console.log('[Agora] Received existing user identities:', data);
        data.identities.forEach(identity => {
            agoraUidToNameMap[identity.agora_uid] = identity.display_name;
        });
    });

});

function renderChatMessage(data, currentChatUsername) {
    const chatMessages = document.getElementById('chat-messages');
    if (!chatMessages) return;

    const msgDiv = document.createElement('div');
    msgDiv.className = `chat-message ${data.username === currentChatUsername ? 'sent' : 'received'}`;
    
    if (data.username === 'System') {
        msgDiv.className = 'chat-message system-message';
        if (typeof addNotification === 'function' && data.message.toLowerCase().includes('changed their name to')) {
             addNotification('Chat Info', data.message, 'info');
        }
        msgDiv.textContent = data.message;
        chatMessages.appendChild(msgDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
        return;
    }

    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    const avatarCircle = document.createElement('div');
    avatarCircle.className = 'avatar-circle';
    avatarCircle.textContent = data.username ? data.username.substring(0, 2).toUpperCase() : '??';
    avatar.appendChild(avatarCircle);

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';

    const header = document.createElement('div');
    header.className = 'message-header';
    
    const sender = document.createElement('span');
    sender.className = 'message-sender';
    sender.textContent = data.username;
    header.appendChild(sender);

    const time = document.createElement('span');
    time.className = 'message-time';
    time.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); // Use current time for new messages
    header.appendChild(time);

    const content = document.createElement('div');
    content.className = 'message-content';
    content.textContent = data.message;

    bubble.appendChild(header);
    bubble.appendChild(content);

    if (data.username === currentChatUsername) {
        msgDiv.appendChild(bubble);
        msgDiv.appendChild(avatar);
    } else {
        msgDiv.appendChild(avatar);
        msgDiv.appendChild(bubble);
    }

    chatMessages.appendChild(msgDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Daphinix Chat Functions (Global Scope)
let daphinixMemory = []; // Ensure this is in a scope accessible by other functions if needed

function getDaphinixMemory() {
    return daphinixMemory;
}

function addToDaphinixMemory(role, content) {
    daphinixMemory.push({ role, content });
    // Keep only last 50 messages
    if (daphinixMemory.length > 50) {
        daphinixMemory = daphinixMemory.slice(-50);
    }
}

function clearDaphinixMemory() {
    daphinixMemory = [];
    const responseArea = document.getElementById('responseArea');
    if (responseArea) responseArea.innerHTML = '';
}

async function sendToDaphinix(message, imageFile = null) {
    try {
        let response, data;
        const responseArea = document.getElementById('responseArea');

        // Temporarily use a local memory for Daphinix in study room, or decide if it should be global.
        // For now, let's assume daphinixMemory is local to this function's scope or defined if needed.
        let localDaphinixMemory = []; // Placeholder

        if (imageFile) {
            // Image chat: use FormData
            const formData = new FormData();
            formData.append('message', message);
            // formData.append('memory', JSON.stringify(getDaphinixMemory())); // Using local memory for now
            formData.append('memory', JSON.stringify(localDaphinixMemory));
            formData.append('image', imageFile);

            response = await fetch('/api/chat_with_image', {
                method: 'POST',
                body: formData
            });
        } else {
            // Text chat: use JSON
            response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: message,
                    // memory: getDaphinixMemory() // Using local memory for now
                    memory: localDaphinixMemory
                })
            });
        }

        if (!response.ok) throw new Error('Network response was not ok');
        data = await response.json();
        if (data.error) throw new Error(data.error);

        // Add user message to memory
        // addToDaphinixMemory('user', message); // Modify if using shared memory
        localDaphinixMemory.push({role: 'user', content: message});
        // Add Daphinix response to memory
        // addToDaphinixMemory('assistant', data.response); // Modify if using shared memory
        localDaphinixMemory.push({role: 'assistant', content: data.response});

        // Display the response
        if (responseArea) {
            const userMsgDiv = document.createElement('div');
            userMsgDiv.className = 'mb-4';
            userMsgDiv.innerHTML = `<strong>You:</strong> ${message.replace(/</g, "&lt;").replace(/>/g, "&gt;")}`;
            responseArea.appendChild(userMsgDiv);

            const botMsgDiv = document.createElement('div');
            botMsgDiv.className = 'mb-4';
            // Use marked.parse for markdown, then let MathJax handle LaTeX
            botMsgDiv.innerHTML = `<strong>Daphinix:</strong> ${marked.parse(data.response)}`; 
            responseArea.appendChild(botMsgDiv);
            
            responseArea.scrollTop = responseArea.scrollHeight;

            // Typeset MathJax content
            if (window.MathJax) {
                MathJax.typesetPromise([botMsgDiv])
                    .catch((err) => console.error('MathJax typesetting error:', err));
            }
        }
        

        // Clear input
        const myInput = document.getElementById('myInput');
        if(myInput) myInput.value = '';
        const imagePreviewContainer = document.getElementById('image-preview-container');
        if(imagePreviewContainer) imagePreviewContainer.style.display = 'none';
        const imagePreview = document.getElementById('image-preview');
        if(imagePreview) imagePreview.src = '';


    } catch (error) {
        console.error('Error:', error);
        if(typeof addNotification === 'function') addNotification("Daphinix AI", "Error communicating with Daphinix. Please try again.", "error");
    }
}

function updateStudyRoomTimerDisplay(timeLeft) {
    const minutes = Math.floor(timeLeft / 60);
    const seconds = timeLeft % 60;
    const timerDisplayElement = document.getElementById('shared-timer-display');
    if (timerDisplayElement) {
        timerDisplayElement.textContent = 
        `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
}

function updateSessionLabel(isWorkSession) {
    const sessionLabelElement = document.getElementById('shared-session-label');
    if (sessionLabelElement) {
        sessionLabelElement.textContent = 
        isWorkSession ? 'Work Session' : 'Break Session';
    }
}

async function fetchTimerStateAndSync() {
    try {
        if (!currentRoom) {
            console.warn("currentRoom is not set. Skipping fetchTimerStateAndSync.");
            return;
        }
        const response = await fetch(`/api/room_timer_state/${currentRoom}`);
        const timerState = await response.json();
        
        updateStudyRoomTimerDisplay(timerState.timeLeft);
        updateSessionLabel(timerState.isWorkSession);
        
        // Update duration inputs
        const workDurationInput = document.getElementById('shared-work-duration');
        const breakDurationInput = document.getElementById('shared-break-duration');
        if (workDurationInput) workDurationInput.value = timerState.workDuration;
        if (breakDurationInput) breakDurationInput.value = timerState.breakDuration;
        
        // Update timer controls
        const startTimerBtn = document.getElementById('start-shared-timer');
        const pauseTimerBtn = document.getElementById('pause-shared-timer');

        if (startTimerBtn && pauseTimerBtn) {
        if (timerState.isRunning) {
                startTimerBtn.classList.add('hidden');
                pauseTimerBtn.classList.remove('hidden');
        } else {
                startTimerBtn.classList.remove('hidden');
                pauseTimerBtn.classList.add('hidden');
            }
        }
    } catch (error) {
        console.error('Error fetching timer state:', error);
    }
}

// Helper function to play sounds
function playSound(soundId) {
    const sound = document.getElementById(soundId);
    if (sound) {
        sound.currentTime = 0;
        sound.play().catch(e => console.warn(`Error playing sound ${soundId}:`, e));
    }
}

async function initVideoCall() {
    console.log('[Agora] Initializing video call...');

    // 1. Create Agora client
    agoraClient = AgoraRTC.createClient({ mode: 'rtc', codec: 'vp8' });

    try {
        // 2. Fetch token from server
        const response = await fetch(`/api/get_agora_token?channelName=${currentRoom}`);
        const data = await response.json();
        if (data.error) {
            throw new Error(`Agora token error: ${data.error}`);
        }
        agoraAppId = data.appId;
        agoraUid = data.uid;
        const token = data.token;
        
        // Add own identity to the map
        agoraUidToNameMap[agoraUid] = currentUsername;

        // 3. Join channel
        await agoraClient.join(agoraAppId, currentRoom, token, agoraUid);
        console.log(`[Agora] Successfully joined channel ${currentRoom} with UID ${agoraUid}`);

        // Handle remote users
        agoraClient.on('user-published', handleUserPublished);
        agoraClient.on('user-left', handleUserLeft);

        // 4. Create and publish local video track (no audio)
        localVideoTrack = await AgoraRTC.createCameraVideoTrack();
        
        // Create player wrapper and container
        const localPlayerWrapper = document.createElement('div');
        localPlayerWrapper.className = 'video-player-wrapper';

        const localPlayerContainer = document.createElement('div');
        localPlayerContainer.id = `player-container-${agoraUid}`;
        localPlayerContainer.className = 'video-player-container is-local';
        
        localPlayerWrapper.appendChild(localPlayerContainer);
        
        // Add wrapper to the grid
        document.getElementById('video-grid-container').append(localPlayerWrapper);

        // Play video in the container, this will create child elements from Agora
        localVideoTrack.play(localPlayerContainer);

        // NOW, add the user info overlay on top (inside container)
        const userInfo = document.createElement('div');
        userInfo.className = 'video-user-info';
        userInfo.innerHTML = `<span class="username">${currentUsername} (You)</span>`;
        localPlayerContainer.appendChild(userInfo);

        // Add Video Controls (inside wrapper)
        const controlsContainer = document.createElement('div');
        controlsContainer.className = 'video-controls';

        const videoBtn = document.createElement('button');
        videoBtn.id = 'toggle-video-btn';
        videoBtn.className = 'control-btn';
        videoBtn.innerHTML = '<i class="fas fa-video"></i>';
        videoBtn.title = 'Turn camera off';

        videoBtn.addEventListener('click', () => {
            if (localVideoTrack.enabled) {
                localVideoTrack.setEnabled(false);
                videoBtn.innerHTML = '<i class="fas fa-video-slash"></i>';
                videoBtn.title = 'Turn camera on';
                videoBtn.classList.add('danger');
            } else {
                localVideoTrack.setEnabled(true);
                videoBtn.innerHTML = '<i class="fas fa-video"></i>';
                videoBtn.title = 'Turn camera off';
                videoBtn.classList.remove('danger');
            }
        });

        controlsContainer.appendChild(videoBtn);
        localPlayerWrapper.appendChild(controlsContainer);

        await agoraClient.publish([localVideoTrack]);
        console.log('[Agora] Local video track published');

    } catch (error) {
        console.error('[Agora] Failed to initialize video call', error);
        const videoPanel = document.getElementById('video-panel');
        
        let userFriendlyMessage = 'Could not start video call. Please check console for errors and make sure camera permissions are allowed.';

        // Check for specific Agora SDK error codes to provide better user feedback
        if (error && error.code) {
            switch (error.code) {
                case 'PERMISSION_DENIED':
                    userFriendlyMessage = 'Camera permission denied. Please allow camera access in your browser settings and refresh the page.';
                    break;
                case 'DEVICE_NOT_FOUND':
                    userFriendlyMessage = 'No camera device found. Please ensure a camera is connected and enabled.';
                    break;
                case 'DEVICE_IN_USE':
                    userFriendlyMessage = 'The camera is already in use by another application. Please close it and refresh the page.';
                    break;
                default:
                    console.log(`[Agora] Unhandled error code: ${error.code}`);
                    break;
            }
        }

        if (videoPanel) {
            videoPanel.innerHTML = `<div class="text-red-400 text-center p-8">${userFriendlyMessage}</div>`;
        }
        if(typeof addNotification === 'function') {
            addNotification("Video Error", userFriendlyMessage, "error");
        }
    }
}

async function handleUserPublished(user, mediaType) {
    await agoraClient.subscribe(user, mediaType);
    console.log(`[Agora] Subscribed to user ${user.uid}`);

    if (mediaType === 'video') {
        remoteUsers[user.uid] = user;

        const remotePlayerWrapper = document.createElement('div');
        remotePlayerWrapper.className = 'video-player-wrapper';

        const remotePlayerContainer = document.createElement('div');
        remotePlayerContainer.id = `player-container-${user.uid}`;
        remotePlayerContainer.className = 'video-player-container';
        
        remotePlayerWrapper.appendChild(remotePlayerContainer);
        
        const displayName = agoraUidToNameMap[user.uid] || `User ${user.uid}`;
        
        // Add wrapper to grid
        document.getElementById('video-grid-container').append(remotePlayerWrapper);
        
        // Play video track first
        user.videoTrack.play(remotePlayerContainer);
        
        // THEN add user info overlay
        const userInfo = document.createElement('div');
        userInfo.className = 'video-user-info';
        userInfo.innerHTML = `<span class="username" id="username-${user.uid}">${displayName}</span>`;
        remotePlayerContainer.appendChild(userInfo);
    }
}

function handleUserLeft(user) {
    delete remoteUsers[user.uid];
    const playerWrapper = document.getElementById(`player-container-${user.uid}`)?.closest('.video-player-wrapper');
    if (playerWrapper) {
        playerWrapper.remove();
    }
    console.log(`[Agora] User ${user.uid} left`);
}

async function leaveVideoCall() {
    // Stop and close the local video track
    if (localVideoTrack) {
        localVideoTrack.stop();
        localVideoTrack.close();
        localVideoTrack = null;
    }
    // Leave the Agora channel
    if (agoraClient) {
        await agoraClient.leave();
        agoraClient = null;
        console.log('[Agora] Left video channel');
    }
    // Clear the video grid
    const videoGrid = document.getElementById('video-grid-container');
    if (videoGrid) videoGrid.innerHTML = '';
    // Clear the user map
    agoraUidToNameMap = {};
    remoteUsers = {};
}

// Utility: Disable/Enable timer controls
function setTimerControlsEnabled(enabled) {
    const startBtn = document.getElementById('start-shared-timer');
    const pauseBtn = document.getElementById('pause-shared-timer');
    const resetBtn = document.getElementById('reset-shared-timer');
    [startBtn, pauseBtn, resetBtn].forEach(btn => {
        if (btn) btn.disabled = !enabled;
        if (btn) btn.classList.toggle('disabled', !enabled);
    });
    // Optional: show spinner or overlay
    const timerPanel = document.getElementById('timer-panel');
    let spinner = document.getElementById('timer-sync-spinner');
    if (!enabled) {
        if (!spinner && timerPanel) {
            spinner = document.createElement('div');
            spinner.id = 'timer-sync-spinner';
            spinner.innerHTML = '<div class="loader"></div><div class="text-white text-center mt-2">Syncing timer...</div>';
            spinner.style.position = 'absolute';
            spinner.style.top = '50%';
            spinner.style.left = '50%';
            spinner.style.transform = 'translate(-50%, -50%)';
            spinner.style.zIndex = '100';
            timerPanel.appendChild(spinner);
        }
    } else {
        if (spinner && timerPanel) timerPanel.removeChild(spinner);
    }
}

// Initially disable timer controls until sync
setTimerControlsEnabled(false);
let timerReady = false;
