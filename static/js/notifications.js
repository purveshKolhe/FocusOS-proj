// Centralized notification logic using Firebase (notifications.js)

// Assume firebase and firebase.firestore() are initialized and available globally.
// A global variable to hold the Firestore database instance. Will be set by Firebase SDK.
// let db; 
// Example: if Firebase is initialized, db = firebase.firestore();

let currentUserId_notifications = null;
let notificationsListenerUnsubscribe_notifications = null;
let globalNotificationsArray_notifications = []; // Local cache of notifications
let globalUnreadCount_notifications = 0;
let lastKnownNotificationCount = 0; // To track if new notifications arrived

/**
 * Plays a sound by its ID.
 * @param {string} soundId The ID of the audio element.
 */
function playNotificationSound(soundId) {
    console.log(`[Notifications.js] playNotificationSound called with soundId: ${soundId}`);
    const sound = document.getElementById(soundId);
    if (sound) {
        console.log(`[Notifications.js] Found sound element:`, sound);
        sound.currentTime = 0;
        sound.play().catch(e => console.warn(`[Notifications.js] Error playing sound ${soundId}:`, e.name, e.message));
    } else {
        console.warn(`[Notifications.js] Sound element with ID '${soundId}' not found for notification.`);
    }
}

/**
 * Initializes the global notification system.
 * Sets up Firebase listeners for user-specific notifications.
 * @param {string} userId The ID of the current user.
 */
async function initializeGlobalNotificationSystem(userId) {
    console.log(`[Notifications.js] initializeGlobalNotificationSystem called for userId: ${userId}`);
    if (!userId) {
        console.error("[Notifications.js] User ID is required to initialize notifications.");
        return;
    }
    currentUserId_notifications = userId;

    if (typeof firebase === 'undefined' || typeof firebase.firestore === 'undefined') {
        console.error("[Notifications.js] Firebase or Firestore is not available. Notifications will not work.");
        const panel = document.getElementById('notification-panel');
        if (panel) {
            panel.innerHTML = '<div style="padding: 10px; color: red;">Error: Notification system could not connect to the database.</div>';
        }
        return;
    }
    const db = firebase.firestore();

    if (notificationsListenerUnsubscribe_notifications) {
        console.log("[Notifications.js] Unsubscribing from previous notifications listener.");
        notificationsListenerUnsubscribe_notifications();
    }

    const notificationsRef = db.collection('users').doc(currentUserId_notifications).collection('notifications').orderBy('timestamp', 'desc');

    console.log(`[Notifications.js] Setting up onSnapshot listener for path: users/${currentUserId_notifications}/notifications`);
    notificationsListenerUnsubscribe_notifications = notificationsRef.onSnapshot(snapshot => {
        console.log("[Notifications.js] onSnapshot triggered.");
        const newNotificationsArray = [];
        let newUnreadCount = 0;
        snapshot.forEach(doc => {
            const notification = { id: doc.id, ...doc.data() };
            newNotificationsArray.push(notification);
            if (!notification.read) {
                newUnreadCount++;
            }
        });
        console.log("[Notifications.js] Snapshot data processed. newNotificationsArray:", newNotificationsArray, "newUnreadCount:", newUnreadCount);

        // Log current state BEFORE updating and checking for sound
        console.log(`[Notifications.js] State BEFORE sound check: lastKnownNotificationCount: ${lastKnownNotificationCount}, globalUnreadCount_notifications: ${globalUnreadCount_notifications}`);
        
        const shouldPlaySound = newNotificationsArray.length > lastKnownNotificationCount && newUnreadCount > globalUnreadCount_notifications;
        console.log(`[Notifications.js] Condition for playing sound (newTotal > lastKnownTotal && newUnread > lastKnownUnread): ${newNotificationsArray.length} > ${lastKnownNotificationCount} && ${newUnreadCount} > ${globalUnreadCount_notifications} === ${shouldPlaySound}`);

        if (shouldPlaySound) {
            console.log("[Notifications.js] Attempting to play 'sound-levelup' due to new unread notification.");
            playNotificationSound('sound-levelup');
        }
        
        globalNotificationsArray_notifications = newNotificationsArray;
        globalUnreadCount_notifications = newUnreadCount;
        lastKnownNotificationCount = newNotificationsArray.length;
        console.log(`[Notifications.js] State AFTER update: lastKnownNotificationCount: ${lastKnownNotificationCount}, globalUnreadCount_notifications: ${globalUnreadCount_notifications}`);


        renderGlobalNotifications(globalNotificationsArray_notifications);
        updateGlobalNotificationBadge(globalUnreadCount_notifications);
    }, error => {
        console.error("[Notifications.js] Error listening to notifications:", error);
        const panel = document.getElementById('notification-panel');
        if (panel) {
            panel.innerHTML = '<div style="padding: 10px; color: red;">Could not load notifications.</div>';
        }
    });

    attachGlobalUIEventListeners();
    console.log('[Notifications.js] Global notification system initialized and UI listeners attached for user:', currentUserId_notifications);
}

/**
 * Attaches event listeners to the notification UI elements.
 */
function attachGlobalUIEventListeners() {
    const bell = document.getElementById('notification-bell');
    const panel = document.getElementById('notification-panel');
    const clearBtn = document.getElementById('clear-notifications');

    if (bell && panel) {
        // Clone and replace to remove old listeners
        const newBell = bell.cloneNode(true);
        if (bell.parentNode) {
            bell.parentNode.replaceChild(newBell, bell);
        }
        
        newBell.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            panel.classList.toggle('hidden');
            if (!panel.classList.contains('hidden')) {
                // Mark all as read when panel is opened
                markAllCurrentUserNotificationsAsRead();
            }
        });

        // Close panel when clicking outside
        document.addEventListener('click', function(e) {
            if (panel && newBell && !panel.classList.contains('hidden') && !panel.contains(e.target) && !newBell.contains(e.target)) {
                panel.classList.add('hidden');
            }
        });

        if (clearBtn) {
            const newClearBtn = clearBtn.cloneNode(true);
            if (clearBtn.parentNode) {
                clearBtn.parentNode.replaceChild(newClearBtn, clearBtn);
            }
            newClearBtn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                clearAllCurrentUserNotifications();
            });
        }
    } else {
        console.warn('[Notifications.js] Notification UI elements (bell or panel) not found for global system.');
    }
}

/**
 * Adds a new notification to Firebase for the current user.
 * @param {string} title The title of the notification.
 * @param {string} content The content of the notification.
 * @param {string} type The type of notification (info, success, warning, error).
 */
async function addNotification(title, content, type = 'info') {
    console.log(`[Notifications.js] addNotification called with Title: ${title}, Content: ${content}, Type: ${type}, UserID: ${currentUserId_notifications}`);
    if (!currentUserId_notifications) {
        console.error("[Notifications.js] Cannot add notification: User ID not set.");
        return;
    }
    if (typeof firebase === 'undefined' || typeof firebase.firestore === 'undefined') {
        console.error("[Notifications.js] Firebase or Firestore is not available. Cannot add notification.");
        return;
    }
    const db = firebase.firestore();

    try {
        console.log(`[Notifications.js] Attempting to add document to Firestore path: users/${currentUserId_notifications}/notifications`);
        const docRef = await db.collection('users').doc(currentUserId_notifications).collection('notifications').add({
            title: title,
            content: content,
            type: type,
            timestamp: firebase.firestore.FieldValue.serverTimestamp(),
            read: false
        });
        console.log('[Notifications.js] Notification successfully added to Firebase with ID:', docRef.id);
    } catch (error) {
        console.error("[Notifications.js] Error adding notification to Firebase:", error);
    }
}

/**
 * Renders the notifications in the notification panel.
 * @param {Array} notificationsData Array of notification objects.
 */
function renderGlobalNotifications(notificationsData) {
    const list = document.getElementById('notification-list');
    if (!list) {
        // console.warn('Notification list element not found.');
        return;
    }

    list.innerHTML = ''; // Clear existing notifications
    if (notificationsData.length === 0) {
        list.innerHTML = '<div class="notification-item"><div class="notification-content" style="text-align:center; color: #9ca3af;">No notifications yet.</div></div>';
        return;
    }

    notificationsData.forEach(notification => {
        const item = document.createElement('div');
        item.className = `notification-item ${!notification.read ? 'unread' : ''}`;
        item.dataset.id = notification.id;
        
        let formattedTimestamp = 'Just now';
        if (notification.timestamp) {
            // Check if it's a Firebase Timestamp object
            if (notification.timestamp.toDate) {
                 formattedTimestamp = formatFirebaseTimestamp(notification.timestamp.toDate());
            } else if (typeof notification.timestamp === 'string') { // Or an ISO string
                formattedTimestamp = formatFirebaseTimestamp(new Date(notification.timestamp));
            } else {
                formattedTimestamp = 'Invalid date';
            }
        }


        item.innerHTML = `
            <div class="notification-header">
                <span class="notification-title">${notification.title || 'Notification'}</span>
                <span class="notification-time">${formattedTimestamp}</span>
            </div>
            <div class="notification-content">${notification.content || ''}</div>
        `;
        list.appendChild(item);
    });
}

/**
 * Updates the notification badge count.
 * @param {number} count The number of unread notifications.
 */
function updateGlobalNotificationBadge(count) {
    const badge = document.getElementById('notification-badge');
    if (badge) {
        if (count > 0) {
            badge.textContent = count;
            badge.classList.remove('hidden');
        } else {
            badge.textContent = '0'; // Keep it 0 instead of hiding to maintain layout if desired
            badge.classList.add('hidden');
        }
    }
}

/**
 * Marks all unread notifications for the current user as read in Firebase.
 */
async function markAllCurrentUserNotificationsAsRead() {
    if (!currentUserId_notifications) return;
    if (typeof firebase === 'undefined' || typeof firebase.firestore === 'undefined') return;
    const db = firebase.firestore();

    const notificationsRef = db.collection('users').doc(currentUserId_notifications).collection('notifications');
    const querySnapshot = await notificationsRef.where('read', '==', false).get();

    if (querySnapshot.empty) {
        return; // No unread notifications
    }

    const batch = db.batch();
    querySnapshot.forEach(doc => {
        batch.update(doc.ref, { read: true });
    });

    try {
        await batch.commit();
        console.log('[Notifications.js] All unread notifications marked as read.');
    } catch (error) {
        console.error("[Notifications.js] Error marking notifications as read:", error);
    }
}

/**
 * Deletes all notifications for the current user from Firebase.
 */
async function clearAllCurrentUserNotifications() {
    if (!currentUserId_notifications) return;
    if (typeof firebase === 'undefined' || typeof firebase.firestore === 'undefined') return;
    const db = firebase.firestore();

    const notificationsRef = db.collection('users').doc(currentUserId_notifications).collection('notifications');
    const querySnapshot = await notificationsRef.get();

    if (querySnapshot.empty) {
        return; // No notifications to delete
    }

    const batch = db.batch();
    querySnapshot.forEach(doc => {
        batch.delete(doc.ref);
    });

    try {
        await batch.commit();
        console.log('[Notifications.js] All notifications cleared.');
        // The listener will automatically update the UI
    } catch (error) {
        console.error("[Notifications.js] Error clearing notifications:", error);
    }
}

/**
 * Formats a Firebase timestamp (or Date object) into a readable string.
 * @param {Date} dateObject The Date object to format.
 * @returns {string} A formatted string like "5m ago", "1h ago", "Yesterday", or "MMM D".
 */
function formatFirebaseTimestamp(dateObject) {
    if (!(dateObject instanceof Date) || isNaN(dateObject)) {
        return 'Invalid date';
    }

    const now = new Date();
    const diffSeconds = Math.round((now.getTime() - dateObject.getTime()) / 1000);
    const diffMinutes = Math.round(diffSeconds / 60);
    const diffHours = Math.round(diffMinutes / 60);
    const diffDays = Math.round(diffHours / 24);

    if (diffSeconds < 60) {
        return `${diffSeconds}s ago`;
    } else if (diffMinutes < 60) {
        return `${diffMinutes}m ago`;
    } else if (diffHours < 24) {
        return `${diffHours}h ago`;
    } else if (diffDays === 1) {
        return 'Yesterday';
    } else if (diffDays < 7) {
        return `${diffDays}d ago`;
    } else {
        // Format as "Mon DD" e.g. "Jan 23"
        return dateObject.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }
}

/**
 * Shows a temporary, non-blocking toast-style notification on the screen.
 * These are different from the bell notifications.
 * @param {string} message The message to display.
 * @param {string} type The type of notification (info, success, warning, error) for styling.
 * @param {number} duration Duration in milliseconds before the notification disappears.
 */
function showToastNotification(message, type = 'info', duration = 3000) {
    const container = document.getElementById('notification-container') || createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `notification toast ${type}`; // Add 'toast' class for specific styling if needed
    toast.textContent = message;

    // Prepend to show newest on top
    container.insertBefore(toast, container.firstChild);

    setTimeout(() => {
        toast.style.animation = 'slideOut 0.5s forwards';
        toast.addEventListener('animationend', () => {
            toast.remove();
            if (!container.hasChildNodes()) {
                // Optional: remove container if empty and it was dynamically created
                // if (container.id === 'dynamic-toast-container') container.remove();
            }
        });
    }, duration);
}

/**
 * Creates a container for toast notifications if one doesn't exist.
 */
function createToastContainer() {
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container'; // Use the ID defined in base.html
        // Styles for this container are in base.html (fixed top-right)
        // container.style.position = 'fixed';
        // container.style.top = '20px';
        // container.style.right = '20px';
        // container.style.zIndex = '10000'; // Ensure it's on top
        // container.style.display = 'flex';
        // container.style.flexDirection = 'column';
        // container.style.gap = '10px';
        document.body.appendChild(container);
    }
    return container;
}

// Make functions globally available if they aren't already (e.g. if using modules in future)
window.initializeGlobalNotificationSystem = initializeGlobalNotificationSystem;
window.addNotification = addNotification; // For adding to Firebase (bell icon)
window.showToastNotification = showToastNotification; // For temporary on-screen messages

/**
 * Call this function from your main scripts (script.js, study_room.js)
 * after you have the user's ID.
 * Example:
 *   fetch('/api/user_data').then(res => res.json()).then(data => {
 *       if (data.username) { // Assuming username is the userId or can derive it
 *           initializeGlobalNotificationSystem(data.username);
 *           // Add a welcome notification if it's the main page, for example
 *           if (window.location.pathname === '/' || window.location.pathname === '/index.html') {
 *              // Check if welcome notification was already sent for this session to avoid spam
 *              if (!sessionStorage.getItem('welcomeNotificationSent')) {
 *                  addNotification('Welcome!', 'You have successfully logged in.', 'success');
 *                  sessionStorage.setItem('welcomeNotificationSent', 'true');
 *              }
 *           }
 *       }
 *   });
 *
 * IMPORTANT: Ensure Firebase JS SDK is initialized before this script runs
 * and \`firebase.firestore()\` is available.
 * You need to include Firebase SDKs in your HTML:
 * <!-- Firebase App (the core Firebase SDK) is always required and must be listed first -->
 * <script src="https://www.gstatic.com/firebasejs/8.10.0/firebase-app.js"></script>
 * <!-- Add Firestore -->
 * <script src="https://www.gstatic.com/firebasejs/8.10.0/firebase-firestore.js"></script>
 * <script>
 *   // Your web app's Firebase configuration
 *   var firebaseConfig = {
 *     apiKey: "YOUR_FIREBASE_API_KEY",
 *     authDomain: "YOUR_FIREBASE_AUTH_DOMAIN",
 *     projectId: "YOUR_FIREBASE_PROJECT_ID",
 *     // ... other config values
 *   };
 *   // Initialize Firebase
 *   if (!firebase.apps.length) {
 *     firebase.initializeApp(firebaseConfig);
 *   }
 *   // const db = firebase.firestore(); // db can be used globally or passed around
 * </script>
 */ 