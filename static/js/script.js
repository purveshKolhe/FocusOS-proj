document.addEventListener('DOMContentLoaded', function() {
    let audioUnlocked = false;
    function unlockAudio() {
        if (audioUnlocked) return;
        const soundIds = ['sound-click', 'sound-levelup', 'sound-complete', 'ambient-rain', 'ambient-forest', 'ambient-cafe'];
        let unlockedCount = 0;

        soundIds.forEach(id => {
            const sound = document.getElementById(id);
            if (sound) {
                const originalVolume = sound.volume;
                const originallyMuted = sound.muted;
                
                sound.volume = 0.001; // Play very quietly
                sound.muted = false;   // Ensure not muted for the play attempt
                
                // Attempt to play and then immediately pause and reset
                const playPromise = sound.play();
                if (playPromise !== undefined) {
                    playPromise.then(() => {
                        sound.pause();
                        sound.currentTime = 0;
                        sound.volume = originalVolume;
                        sound.muted = originallyMuted;
                        unlockedCount++;
                        if (unlockedCount === 1) {
                            console.log('[Main Interface] Audio context unlocked by user interaction for at least one sound.');
                        }
                    }).catch(error => {
                        // Restore original state even if play failed (e.g. element not ready, but interaction occurred)
                        sound.volume = originalVolume;
                        sound.muted = originallyMuted;
                        // console.warn(`[Main Interface] Failed to play/unlock sound ${id} on interaction:`, error.name, error.message);
                    });
                } else {
                    // Fallback for browsers that don't return a promise (older)
                    try {
                        sound.pause();
                        sound.currentTime = 0;
                        sound.volume = originalVolume;
                        sound.muted = originallyMuted;
                    } catch (e) { /* ignore */ }
                }
            }
        });
        audioUnlocked = true; // Set to true after the first attempt
        // console.log('[Main Interface] unlockAudio function executed.');
        // Listeners are automatically removed due to { once: true }
    }

    // Add event listeners that will run only once
    document.addEventListener('click', unlockAudio, { once: true });
    document.addEventListener('keydown', unlockAudio, { once: true }); // Also unlock on keydown
    document.addEventListener('touchstart', unlockAudio, { once: true }); // For touch devices

    // Global variable to store gamification settings (badges, quests definitions)
    let gamificationSettings = {
        badges: {},
        quests: {},
        leveling: { baseXpForLevelUp: 100 } // Default leveling
    };
    let currentUserProgress = {}; // To store the latest progress from server

    try {
        // Initialize Particles.js for ambient effect
        if (typeof particlesJS !== 'undefined') {
            particlesJS('particles-js', {
                "particles": {
                    "number": {
                        "value": 50,
                        "density": {
                            "enable": true,
                            "value_area": 800
                        }
                    },
                    "color": {
                        "value": "#ffffff"
                    },
                    "shape": {
                        "type": "circle"
                    },
                    "opacity": {
                        "value": 0.3,
                        "random": true,
                        "anim": {
                            "enable": true,
                            "speed": 1,
                            "opacity_min": 0.1,
                            "sync": false
                        }
                    },
                    "size": {
                        "value": 3,
                        "random": true,
                        "anim": {
                            "enable": true,
                            "speed": 2,
                            "size_min": 0.1,
                            "sync": false
                        }
                    },
                    "line_linked": {
                        "enable": false
                    },
                    "move": {
                        "enable": true,
                        "speed": 1,
                        "direction": "top",
                        "random": true,
                        "straight": false,
                        "out_mode": "out",
                        "bounce": false
                    }
                },
                "interactivity": {
                    "detect_on": "canvas",
                    "events": {
                        "onhover": {
                            "enable": false
                        },
                        "onclick": {
                            "enable": false
                        }
                    }
                },
                "retina_detect": true
            });
        } else {
            console.warn("Particles.js is not loaded");
        }

        // Verify jQuery is loaded
        if (typeof $ === 'undefined') {
            console.error("jQuery is not loaded. Event listeners will not work properly.");
            useVanillaJS();
        } else {
            console.log("jQuery loaded successfully. Version:", $.fn.jquery);
            initializeWithJQuery();
        }
    } catch (error) {
        console.error("An error occurred in script.js:", error);
        // Use the global addNotification if available, otherwise fallback to alert
        if (typeof addNotification === 'function') {
            addNotification("Application Error", "Error initializing application.", "error");
        } else {
            alert("Error initializing application. Some features may be impaired.");
        }
    }
    
    // Vanilla JS fallback if jQuery is not loaded
    function useVanillaJS() {
        const materialsYesButton = document.getElementById('materials-yes');
        if (materialsYesButton) {
            materialsYesButton.addEventListener('click', function() {
                console.log("Materials Yes button clicked (vanilla JS)");
                const modal = document.getElementById('checklist-modal');
                modal.style.display = 'none';
                const workspace = document.getElementById('workspace');
                workspace.classList.remove('hidden');
                workspace.style.display = 'block';
                console.log("Checklist completed, showing workspace (vanilla JS)");
            });
        } else {
            console.error("Materials Yes button not found in DOM (vanilla JS)");
        }
    }
    
    // jQuery initialization
    function initializeWithJQuery() {
        // Sound effect function
        function playSound(id) {
            const sound = document.getElementById(id);
            if (sound && !sound.muted) { // Check if sound is not globally muted by the toggle
                sound.currentTime = 0;
                sound.play().catch(e => console.warn(`Error playing sound ${id}:`, e.message));
            }
        }
        window.playSound = playSound; // Expose to global scope
        
        // Function to handle media errors (images/videos in grid)
        function handleMediaError(element, mediaName) {
            console.error(`Media preview failed to load for ${mediaName}: ${element.src}. Hiding element.`);
            element.style.display = 'none'; // Hide the broken media element
            // Optionally, you could replace it with a placeholder or show a text message in its card
            const parentCard = $(element).closest('.background-item-card');
            if (parentCard.length && !parentCard.find('.media-error-message').length) {
                parentCard.append('<p class="media-error-message text-xs text-red-400">Preview unavailable</p>');
            }
        }
        window.handleMediaError = handleMediaError; // Expose if needed by other scripts, though likely not

        function createConfetti() {
            if (typeof confetti === 'function') {
                confetti({
                    particleCount: 100,
                    spread: 70,
                    origin: { y: 0.6 }
                });
            } else {
                console.warn('Confetti function not loaded or available.');
            }
        }
        
        // Notification system (local to script.js for main page)
        // THIS LOCAL SYSTEM IS NOW DEPRECATED in favor of the global notifications.js system.
        // Calls to showNotification below will be changed to addNotification.
        // The UI for toasts will be handled by notifications.js's showToastNotification.
        /*
        let notifications = [];
        let unreadCount = 0;

        function showNotification(title, content, type = 'info') { // THIS IS THE LOCAL ONE
            // ... implementation ... // This will be replaced by addNotification or showToastNotification
        }
        */
        // Helper to decide if a notification is purely for local toast or should be global
        function showUIMessage(title, content, type = 'info', makeGlobal = false) {
            if (makeGlobal) {
                if (typeof addNotification === 'function') {
                    addNotification(title, content, type);
                } else {
                    console.warn("addNotification (global) not available. Falling back to local toast for:", title);
                    if(typeof showToastNotification === 'function') showToastNotification(`${title}: ${content}`, type);
                    else alert(`${title}: ${content}`);
                }
            } else {
                if(typeof showToastNotification === 'function') { // From notifications.js
                    showToastNotification(`${title}: ${content}`, type);
                } else {
                    alert(`${title}: ${content}`); // Absolute fallback
                }
            }
        }

        function createToastContainer() {
            let container = document.getElementById('notification-container');
            if (!container) {
                container = document.createElement('div');
                container.id = 'notification-container';
                container.className = 'fixed top-24 right-4 z-50 flex flex-col space-y-2 items-end';
                document.body.appendChild(container);
            }
            return container;
        }

        function updateNotificationBadge() {
            const badge = document.getElementById('notification-badge');
            if (badge) {
                if (unreadCount > 0) {
                    badge.textContent = unreadCount;
                    badge.classList.remove('hidden');
                } else {
                    badge.classList.add('hidden');
                }
            }
        }

        function renderNotifications() {
            const list = document.getElementById('notification-list');
            if (!list) return;
            
            list.innerHTML = notifications.map(notification => `
                <div class="notification-item ${notification.read ? '' : 'unread'}" data-id="${notification.id}">
                    <div class="notification-header">
                        <span class="notification-title">${notification.title}</span>
                        <span class="notification-time">${formatTimestamp(notification.timestamp)}</span>
                    </div>
                    <div class="notification-content">${notification.content}</div>
                </div>
            `).join('');
             if (notifications.length === 0) {
                list.innerHTML = '<div class="notification-item"><div class="notification-content text-center text-gray-400">No notifications yet.</div></div>';
            }
        }

        function clearNotifications() {
            notifications = [];
            unreadCount = 0;
            updateNotificationBadge();
            renderNotifications();
        }

        function markAllAsRead() {
            notifications.forEach(notification => notification.read = true);
            unreadCount = 0;
            updateNotificationBadge();
            renderNotifications();
        }

        function formatTimestamp(date) {
            const now = new Date();
            const diff = now - date;
            
            if (diff < 60000) { return 'Just now'; }
            else if (diff < 3600000) { const m = Math.floor(diff / 60000); return `${m}m ago`; }
            else if (diff < 86400000) { const h = Math.floor(diff / 3600000); return `${h}h ago`; }
            else { return date.toLocaleDateString(); }
        }

        // Auto grow text box function
        window.autoGrowTextBox = function(element) {
            element.style.height = "auto"; 
            element.style.height = (element.scrollHeight) + "px";
            // Cap the height
            if (parseInt(element.style.height) > 150) {
                element.style.height = "150px";
                element.style.overflowY = "auto";
            } else {
                element.style.overflowY = "hidden";
            }
        };

        // Scroll to bottom of response area
        function scrollToBottom() {
            const responseArea = document.getElementById("responseArea");
            if (responseArea) {
                responseArea.scrollTop = responseArea.scrollHeight;
            }
        }

        // Tab Navigation System
        $(".nav-tab").click(function() {
            const targetPanel = $(this).data("target");
            
            // Update active tab styling
            $(".nav-tab").removeClass("active");
            $(this).addClass("active");
            
            // Show target panel and hide others
            $(".content-panel").removeClass("active");
            $("#" + targetPanel).addClass("active");
            
            // Specific actions when a tab is selected
            if (targetPanel === 'guide-panel') {
                renderGamificationGuide(); 
            } else if (targetPanel === 'stats-panel') {
                // When stats tab is clicked, default to showing progress view
                // and ensure the 'Progress' sub-tab button is active.
                $('#stats-sub-panel-progress').addClass('active');
                $('#stats-sub-panel-leaderboard').removeClass('active');
                $('#stats-progress-view').addClass('active');
                $('#stats-leaderboard-view').removeClass('active');
                
                // Also visually update the buttons
                $('#stats-progress-btn').addClass('active-sub-tab');
                $('#stats-leaderboard-btn').removeClass('active-sub-tab');
            }
            
            playSound("sound-click");
        });

        // --- Stats Panel Sub-navigation (Progress vs Leaderboard) ---
        $('#stats-progress-btn').click(function() {
            if ($(this).hasClass('active-sub-tab')) return;

            // Update button styles
            $(this).addClass('active-sub-tab');
            $('#stats-leaderboard-btn').removeClass('active-sub-tab');

            // Show progress view, hide leaderboard view
            $('#stats-progress-view').addClass('active');
            $('#stats-leaderboard-view').removeClass('active');
            
            playSound("sound-click");
        });

        $('#stats-leaderboard-btn').click(function() {
            if ($(this).hasClass('active-sub-tab')) return;

            // Update button styles
            $(this).addClass('active-sub-tab');
            $('#stats-progress-btn').removeClass('active-sub-tab');
            
            // Show leaderboard view, hide progress view
            $('#stats-leaderboard-view').addClass('active');
            $('#stats-progress-view').removeClass('active');

            // Fetch leaderboard data when this view is shown
            fetchAndRenderLeaderboard('xp'); 
            // Also ensure the XP leaderboard type is selected by default
            $('#leaderboard-xp-btn').addClass('bg-indigo-500').removeClass('bg-gray-700');
            $('#leaderboard-streak-btn').removeClass('bg-indigo-500').addClass('bg-gray-700');
            
            playSound("sound-click");
        });

        // Checklist Logic
        if (typeof $ !== 'undefined' && $("#checklist-modal").length) {
            $("#checklist-modal").show();
            console.log("Checklist modal should be visible");

            $("#social-yes").click(function() {
                console.log("Social Yes button clicked");
                $("#checklist-step-1").hide();
                $("#checklist-step-2").show();
                console.log("Proceeding to checklist step 2");
                playSound("sound-click");
            });

            $("#social-no").click(function() {
                console.log("Social No button clicked");
                // showNotification("Please turn off all social media notifications to proceed.", "warning");
                showUIMessage("Study Prep", "Please turn off all social media notifications to proceed.", "warning", true);
                playSound("sound-click");
            });

            if ($("#materials-yes").length) {
                $("#materials-yes").click(function() {
                    console.log("Materials Yes button clicked (jQuery)");
                    $("#checklist-modal").hide();
                    $("#workspace").removeClass("hidden").show();
                    console.log("Checklist completed, showing workspace (jQuery)");
                    // showNotification("Ready to study! Timer is set for 25 minutes.", "success");
                    showUIMessage("Study Prep", "Ready to study! Timer is set for 25 minutes.", "success", true);
                    playSound("sound-click");
                    // Play rain sound if selected
                    if ($("#ambient-sound-select").val() === "rain") {
                        $("#ambient-rain")[0].play().catch(e => console.warn("Error playing sound:", e));
                    }
                });
            } else {
                // If checklist modal exists but not materials-yes, show workspace anyway
                $("#workspace").removeClass("hidden").show();
            }

            $("#materials-no").click(function() {
                console.log("Materials No button clicked");
                // showNotification("Please gather your study materials and a water bottle.", "warning");
                showUIMessage("Study Prep", "Please gather your study materials and a water bottle.", "warning", true);
                playSound("sound-click");
            });
        } else {
            // If checklist modal does not exist, show workspace by default
            $("#workspace").removeClass("hidden").show();
        }

        // Rules Modal Logic with fixed position in the middle
        $("#rules-button, #rules-button-mobile").click(function() {
            $("#rules-modal").show().css({"display": "flex", "align-items": "center", "justify-content": "center"});
            playSound("sound-click");
        });

        $("#close-rules").click(function() {
            $("#rules-modal").hide();
            playSound("sound-click");
        });
        
        // Close modal when clicking outside
        $(document).on('click', '#rules-modal', function(e) {
            if ($(e.target).is('#rules-modal')) {
                $("#rules-modal").hide();
            }
        });
        
        // Focus Mode
        $("#focus-mode, #focus-mode-mobile").click(function() {
            $("body").toggleClass("focus-mode");
            const isFocusMode = $("body").hasClass("focus-mode");
            
            if (isFocusMode) {
                $("#focus-overlay").removeClass("hidden").css("display", "flex");
                $(this).html('<i class="fas fa-eye-slash"></i>');
                $(this).find(".tooltiptext").text("Exit Focus Mode");
                // showNotification("Focus mode enabled", "info");
                showUIMessage("Focus Mode", "Focus mode enabled.", "info", true);
            } else {
                $("#focus-overlay").addClass("hidden");
                $(this).html('<i class="fas fa-eye"></i>');
                $(this).find(".tooltiptext").text("Enter Focus Mode");
                // showNotification("Focus mode disabled", "info");
                showUIMessage("Focus Mode", "Focus mode disabled.", "info", true);
            }
            
            playSound("sound-click");
        });
        
        // Exit Focus Mode Button (use event delegation for robustness)
        $(document).off('click', '#exit-focus').on('click', '#exit-focus', function() {
            console.log("Exit focus mode button clicked");
            $("body").removeClass("focus-mode");
            $("#focus-overlay").css("display", "none");
            $("#focus-mode, #focus-mode-mobile").html('<i class="fas fa-eye"></i>');
            $("#focus-mode, #focus-mode-mobile").find(".tooltiptext").text("Enter Focus Mode");
            // showNotification("Focus mode disabled", "info");
            showUIMessage("Focus Mode", "Focus mode disabled.", "info", true);
            playSound("sound-click");
        });

        // Daphinix Chat Logic
        // Load previous chat history if exists
        async function loadChatHistory() {
            try {
                const response = await fetch('/api/chat_history');
                if (!response.ok) {
                    throw new Error('Failed to load chat history');
                }
                
                const messages = await response.json();
                if (messages && messages.length > 0) {
                    $("#responseArea").empty();
                    messages.forEach(msg => {
                        if (msg.role === 'user') {
                            $("#responseArea").append(`
                                <div class="message user-message">
                                    <div class="message-content">
                                        <div class="message-header">
                                            <span class="message-sender">You</span>
                                        </div>
                                        <div class="message-text">${msg.content}</div>
                                    </div>
                                </div>
                            `);
                        } else if (msg.role === 'assistant') {
                            $("#responseArea").append(`
                                <div class="message bot-message">
                                    <div class="message-content">
                                        <div class="message-header">
                                            <span class="message-sender">Daphinix</span>
                                        </div>
                                        <div class="message-text">${marked.parse(msg.content)}</div>
                                    </div>
                                </div>
                            `);
                        }
                    });
                    scrollToBottom();
                    if (window.MathJax) {
                        MathJax.typesetPromise();
                    }
                }
            } catch (error) {
                console.error('Error loading chat history:', error);
                // showNotification('Error loading chat history', 'error'); // Local toast is fine here
                showUIMessage('Chat Error', 'Error loading chat history', 'error', false);
            }
        }

        // Save chat history to Firebase
        async function saveChatHistory(messages) {
            try {
                const response = await fetch('/api/chat_history', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(messages)
                });
                
                if (!response.ok) {
                    throw new Error('Failed to save chat history');
                }
            } catch (error) {
                console.error('Error saving chat history:', error);
            }
        }

        // Update the sendDaphinixMessage function
        window.sendDaphinixMessage = async function() {
            const inputEl = document.getElementById("myInput");
            const inputVal = inputEl.value.trim();
            const fileInput = document.getElementById("image-upload");
            const hasImage = fileInput && fileInput.files && fileInput.files.length > 0;
            
            if (inputVal === "" && !hasImage) {
                // showNotification("Please type a question or upload an image", "warning"); // Local toast fine
                showUIMessage("Daphinix AI", "Please type a question or upload an image.", "warning", false);
                return;
            }
            
            // Add user message to the chat
            $("#responseArea").append(`
                <div class="message user-message">
                    <div class="message-content">
                        <div class="message-header">
                            <span class="message-sender">You</span>
                        </div>
                        <div class="message-text">${inputVal}</div>
                        ${hasImage ? '<div class="mt-2"><img src="' + URL.createObjectURL(fileInput.files[0]) + '" class="max-w-full rounded" style="max-height: 200px;"></div>' : ''}
                    </div>
                </div>
            `);
            
            // Get current chat history
            const response = await fetch('/api/chat_history');
            const messages = await response.json();
            messages.push({ role: 'user', content: inputVal });
            
            // Clear input
            inputEl.value = '';
            inputEl.style.height = 'auto';
            
            // Show typing indicator
            $("#responseArea").append(`
                <div class="message bot-message typing-message">
                    <div class="message-content">
                        <div class="message-header">
                            <span class="message-sender">Daphinix</span>
                        </div>
                        <div class="typing-indicator">
                            <span></span><span></span><span></span>
                        </div>
                    </div>
                </div>
            `);
            
            scrollToBottom();
            
            try {
            // Send to appropriate API endpoint based on whether there's an image
            if (hasImage) {
                const formData = new FormData();
                formData.append('message', inputVal);
                formData.append('image', fileInput.files[0]);
                    formData.append('memory', JSON.stringify(messages));
                
                    const response = await fetch('/api/chat_with_image', {
                    method: 'POST',
                    body: formData
                    });
                    const data = await response.json();
                    
                    handleDaphinixResponse(data.response);
                    messages.push({ role: 'assistant', content: data.response });
                    await saveChatHistory(messages);
                    
                    // Reset file input
                    fileInput.value = '';
                    $("#image-preview-container").hide();
                    $("#image-preview").attr("src", "");
            } else {
                    const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                        body: JSON.stringify({ message: inputVal, memory: messages }),
                    });
                    const data = await response.json();
                    
                    handleDaphinixResponse(data.response);
                    messages.push({ role: 'assistant', content: data.response });
                    await saveChatHistory(messages);
                }
            } catch (error) {
                    console.error('Error:', error);
                    handleDaphinixError();
            }
        };
        
        // Handle Daphinix response
        function handleDaphinixResponse(responseText) {
            $(".typing-message").remove();
            const botMessage = document.createElement('div');
            botMessage.className = 'bot-message message';
            // Corrected template literal usage
            botMessage.innerHTML = `
                    <div class="message-content">
                    <div class="message-header">
                        <span class="message-sender">Daphinix</span>
                    </div>
                    <div class="message-text">${marked.parse(responseText)}</div>
                        </div>
            `;
            $("#responseArea").append(botMessage);
            scrollToBottom();
            playSound("sound-click");
            if (window.MathJax) {
                MathJax.typesetPromise();
            }
            $("#image-preview-container").hide();
            $("#image-preview").attr("src", "");
        }
        
        // Handle Daphinix error
        function handleDaphinixError() {
            // Remove typing indicator
            $(".typing-message").remove();
            
            // Add error message
            // Corrected template literal usage
            $("#responseArea").append(`
                <div class="message bot-message">
                    <div class="message-content">
                        <div class="message-header">
                            <span class="message-sender">Daphinix</span>
                        </div>
                        <div class="message-text">
                            <p>I'm sorry, I encountered an error processing your request. Please try again later.</p>
                        </div>
                    </div>
                </div>
            `);
            scrollToBottom();
            showUIMessage("Daphinix AI", "Error connecting to Daphinix.", "error", false);
            $("#image-preview-container").hide();
            $("#image-preview").attr("src", "");
        }
        
        // Send message when clicking send button
        $("#send-button").click(function() {
            sendDaphinixMessage();
        });
        
        // Send message when pressing Enter (without Shift)
        $("#myInput").keydown(function(e) {
            if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendDaphinixMessage();
            }
        });
        
        // Auto-grow text area as user types
        $("#myInput").on("input", function() {
            autoGrowTextBox(this);
        });
        
        // Update the clear chat button
        $("#clear-chat").click(async function() {
            $("#responseArea").empty();
            await saveChatHistory([]);
            // showNotification("Chat history cleared", "info"); // Local toast fine
            showUIMessage("Daphinix AI", "Chat history cleared.", "info", false);
            playSound("sound-click");
        });

        // Load chat history when the page loads
        $(document).ready(function() {
            // loadUserData(); // Now called by loadUserDataAndInitNotifications
            loadChatHistory();
        });

        // Pomodoro Timer Logic
        window.isRunning = false;
        window.isPaused = false;
        window.isWorkSession = true;

        // Initialize with defaults if specific inputs are not found or invalid
        let initialWorkVal = parseInt($("#work-duration").val());
        window.workDuration = isNaN(initialWorkVal) ? 25 : initialWorkVal;

        let initialBreakVal = parseInt($("#break-duration").val());
        window.breakDuration = isNaN(initialBreakVal) ? 5 : initialBreakVal;

        window.timeLeft = (window.isWorkSession ? window.workDuration : window.breakDuration) * 60;
        window.totalTime = window.timeLeft; 
        window.timerInterval;

        window.updateTimerDisplay = function() {
            let minutes, seconds;
            if (isNaN(timeLeft) || timeLeft === null || typeof timeLeft === 'undefined') {
                // Fallback if timeLeft is not a number
                // Try to use workDuration, or default to 25 if workDuration is also not set
                const defaultWorkMinutes = (typeof workDuration !== 'undefined' && !isNaN(workDuration)) ? workDuration : 25;
                minutes = defaultWorkMinutes;
                seconds = 0;
                console.warn('[Timer] updateTimerDisplay called with invalid timeLeft. Defaulting to', `${minutes}:00`);
            } else {
                minutes = Math.floor(timeLeft / 60);
                seconds = timeLeft % 60;
            }
            
            const timeString = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
            
            $("#timer-display").text(timeString);
            $("#focus-timer").text(timeString);
            
            // Update document title
            document.title = `${timeString} - FocusOS`;
        }

        window.startTimer = function() {
            if (!isRunning) {
                isRunning = true;
                isPaused = false;
                $("#start-timer").addClass("hidden");
                $("#pause-timer").removeClass("hidden");
                
                totalTime = isWorkSession ? workDuration * 60 : breakDuration * 60;
                
                if (timeLeft === totalTime) {
                    // showNotification(isWorkSession ? "Work session started" : "Break started", "info");
                    showUIMessage("Timer", isWorkSession ? "Work session started." : "Break started.", "info", true);
                } else {
                    // showNotification("Timer resumed", "info");
                    showUIMessage("Timer", "Timer resumed.", "info", true);
                }
                
                timerInterval = setInterval(function() {
                    if (timeLeft > 0) {
                        timeLeft--;
                        updateTimerDisplay();
                    } else {
                        clearInterval(timerInterval);
                        handleTimerComplete();
                    }
                }, 1000);
            }
        }
        
        window.pauseTimer = function() {
            if (isRunning && !isPaused) {
                isRunning = false;
                isPaused = true;
                clearInterval(timerInterval);
                
                $("#pause-timer").addClass("hidden");
                $("#start-timer").removeClass("hidden");
                
                // showNotification("Timer paused", "info");
                showUIMessage("Timer", "Timer paused.", "info", true);
            }
        }
        
        window.resetTimer = function(newWorkDuration, newBreakDuration) {
            clearInterval(timerInterval);
            isRunning = false;
            isPaused = false;
            
            // Use provided durations if available, otherwise read from input fields
            if (typeof newWorkDuration !== 'undefined' && !isNaN(parseInt(newWorkDuration))) {
                workDuration = parseInt(newWorkDuration);
            } else {
                workDuration = parseInt($("#work-duration").val());
            }

            if (typeof newBreakDuration !== 'undefined' && !isNaN(parseInt(newBreakDuration))) {
                breakDuration = parseInt(newBreakDuration);
            } else {
                breakDuration = parseInt($("#break-duration").val());
            }
            
            // Ensure durations are numbers, default to 25/5 if NaN
            if (isNaN(workDuration)) workDuration = 25;
            if (isNaN(breakDuration)) breakDuration = 5;

            timeLeft = isWorkSession ? workDuration * 60 : breakDuration * 60;
            totalTime = timeLeft;
            
            $("#start-timer").removeClass("hidden");
            $("#pause-timer").addClass("hidden");
            
            updateTimerDisplay();
            // showNotification("Timer reset", "info");
            showUIMessage("Timer", "Timer reset.", "info", true);
        }
        
        window.switchSession = function() {
            isWorkSession = !isWorkSession;
            
            if (isWorkSession) {
                $("#session-label").text("Work Session");
                timeLeft = workDuration * 60;
            } else {
                $("#session-label").text("Break");
                timeLeft = breakDuration * 60;
            }
            
            totalTime = timeLeft;
            updateTimerDisplay();
        }
        
        window.handleTimerComplete = function() {
            playSound("sound-complete");
            
            if (isWorkSession) {
                // Work session completed
                showUIMessage("Timer", "Work session completed! Take a break.", "success", true);
                
                // Client-side XP and level calculation is now REMOVED.
                // Server will calculate XP, level, badges, quests, streak based on the event.

                // Add to session history for immediate UI feedback.
                // The authoritative session history is managed by the server.
                addSessionToHistory("work", workDuration); 
                
                // Trigger saveUserData with session completed event
                // This will send the workDuration, and the server will handle all progress updates.
                saveUserData({ event_type: "session_completed", event_data: { duration: workDuration } });

            } else {
                // Break completed
                showUIMessage("Timer", "Break completed! Ready for work?", "success", true);
                addSessionToHistory("break", breakDuration); 
                // Optionally, save data after a break if there's any specific server logic for it
                // or if just to keep sessionHistory on server up-to-date.
                saveUserData(); // Send a general save, no specific event for break completion gamification by default.
            }
            
            // Switch to the other session type
            switchSession();
            
            // Auto-start next session
            startTimer();
        }
        
        // This function is now deprecated. Badge checking is server-side.
        /* function checkForBadges(totalMinutes) { ... } */
        
        function addSessionToHistory(type, duration) {
            const date = new Date();
            // This function primarily updates the UI for immediate feedback.
            // Authoritative session history is managed server-side based on events.

            const displayDateStr = date.toLocaleDateString();
            const displayTimeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const sessionEntryHTML = $(`
                <div class="session-entry bg-gray-700 bg-opacity-50 p-2 rounded mb-2 flex justify-between items-center" data-timestamp="${date.toISOString()}">
                    <div>
                        <span class="text-xs text-gray-400">${displayDateStr} at ${displayTimeStr}</span>
                        <p class="text-sm">${duration} min ${type} session</p>
                    </div>
                    <div class="text-purple-300"><i class="fas fa-check-circle"></i></div>
                </div>
            `);
            
            $("#recent-sessions .text-center").remove(); // Remove "no sessions" message if it exists
            $("#recent-sessions").prepend(sessionEntryHTML);
            
            // Limit to last 10 sessions shown in UI
            const sessionEntriesUI = $("#recent-sessions .session-entry");
            if (sessionEntriesUI.length > 10) {
                sessionEntriesUI.last().remove();
            }
        }
        
        // This function is deprecated. Streak is server-side.
        /* function updateStreak() { ... } */
        
        // Timer control button event handlers
        $("#start-timer").click(function() {
            startTimer();
            playSound("sound-click");
        });
        
        $("#pause-timer").click(function() {
            pauseTimer();
            playSound("sound-click");
        });
        
        $("#reset-timer").click(function() {
            resetTimer();
            playSound("sound-click");
        });
        
        // Ambient sound selection
        $("#ambient-sound-select").change(function() {
            const selection = $(this).val();
            
            // Stop all ambient sounds first
            $("#ambient-rain")[0].pause();
            $("#ambient-forest")[0].pause();
            $("#ambient-cafe")[0].pause();
            
            if (selection === "rain") {
                $("#ambient-rain")[0].play().catch(e => console.warn("Error playing sound:", e));
            } else if (selection === "forest") {
                $("#ambient-forest")[0].play().catch(e => console.warn("Error playing sound:", e));
            } else if (selection === "cafe") {
                $("#ambient-cafe")[0].play().catch(e => console.warn("Error playing sound:", e));
            }
            
            playSound("sound-click");
            
            if (selection !== "none") {
                // showNotification(`${$(this).find("option:selected").text()} sound enabled`, "info");
                showUIMessage("Environment", `${$(this).find("option:selected").text()} sound enabled.`, "info", true);
            } else {
                // showNotification("Ambient sound disabled", "info");
                showUIMessage("Environment", "Ambient sound disabled.", "info", true);
            }
        });
        
        // Volume control for ambient sounds
        $("#volume-slider").on("input", function() {
            const volume = $(this).val() / 100;
            $("#ambient-rain")[0].volume = volume;
            $("#ambient-forest")[0].volume = volume;
            $("#ambient-cafe")[0].volume = volume;
        });
        
        // Toggle sound on/off
        $("#sound-toggle").click(function() {
            const allAudio = $("audio");
            const isMuted = $(this).data("muted") || false;
            
            if (isMuted) {
                allAudio.prop("muted", false);
                $(this).data("muted", false);
                $(this).html('<i class="fas fa-volume-up"></i>');
                // showNotification("Sound enabled", "info");
                showUIMessage("Settings", "Sound enabled.", "info", true);
            } else {
                allAudio.prop("muted", true);
                $(this).data("muted", true);
                $(this).html('<i class="fas fa-volume-mute"></i>');
                // showNotification("Sound disabled", "info");
                showUIMessage("Settings", "Sound disabled.", "info", true);
            }
        });

        $(document).one('click keydown touchstart', function() { // Combined unlock events
            if (!audioUnlocked) { // Ensure this block runs only once as unlockAudio itself is {once: true}
                // The unlockAudio function already handles playing a dummy sound to unlock context.
                // Now, if rain is the selected default, try to play it specifically after this first interaction.
                const selectedSound = $("#ambient-sound-select").val();
                if (selectedSound === "rain") {
                    const rainAudio = $("#ambient-rain")[0];
                    if (rainAudio && rainAudio.paused) { // Check if it's not already playing
                        rainAudio.play().catch(e => console.warn("Error playing default rain sound after interaction:", e));
                    }
                }
            }
        });

        // Event listener for clicking on a background item in the modal grid
        $(document).on('click', '#bg-modal-grid-container .background-item-card', function() {
            const selectedId = $(this).data('id');
            applyPageBackground(selectedId);
            currentSelectedBackgroundId = selectedId; // Update the main variable here
            
            // Update selected state visual on cards within the modal grid
            $('#bg-modal-grid-container .background-item-card').removeClass('selected');
            $(this).addClass('selected');
            
            const selectedOption = backgroundOptions.find(opt => opt.id === selectedId);
            if (selectedOption) {
                $currentBgNameDisplay.text(selectedOption.name);
            }
            playSound("sound-click");
            showUIMessage("Environment", `Background changed to ${selectedOption.name}.`, "info", true);
            // Optionally close modal after selection
            // $backgroundModal.css('display', 'none'); 
        });

        // On page load, initialize UI with static backgrounds
        $(document).ready(function() {
            // loadUserData(); // Now called by loadUserDataAndInitNotifications
            loadChatHistory();
        });

        // Environment settings
        
        // Background selection
        // Define background options with type and category
        const backgroundOptions = [
            // Local Videos (Restored)
            { id: 'video1', name: 'Forest Stream', type: 'video', category: 'nature', path: '/static/assets/videos/forest_stream.webm', preview: '/static/assets/videos/forest_stream.webm' },
            { id: 'video2', name: 'Rainy Window', type: 'video', category: 'ambient', path: '/static/assets/videos/rainy_window.mp4', preview: '/static/assets/videos/rainy_window.mp4' },
            { id: 'video3', name: 'Library Ambience', type: 'video', category: 'study', path: '/static/assets/videos/library_ambience.mp4', preview: '/static/assets/videos/library_ambience.mp4', playbackRate: 0.5 },
            // Hotlinked Videos
            { id: 'hotlink_video_1', name: 'Cityscape', type: 'video', category: 'city', path: 'https://assets.mixkit.co/videos/20093/20093-720.mp4', preview: 'https://assets.mixkit.co/videos/20093/20093-720.mp4' },
            { id: 'hotlink_video_2', name: 'Island Sea', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/2168/2168-720.mp4', preview: 'https://assets.mixkit.co/videos/2168/2168-720.mp4' },
            { id: 'hotlink_video_3', name: 'Rain on Leaves', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/18310/18310-720.mp4', preview: 'https://assets.mixkit.co/videos/18310/18310-720.mp4' },
            { id: 'hotlink_video_4', name: 'Empty Road', type: 'video', category: 'ambient', path: 'https://assets.mixkit.co/videos/41576/41576-720.mp4', preview: 'https://assets.mixkit.co/videos/41576/41576-720.mp4' },
            { id: 'hotlink_video_5', name: 'Waterfall', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/2186/2186-720.mp4', preview: 'https://assets.mixkit.co/videos/2186/2186-720.mp4' },
            { id: 'hotlink_video_6', name: 'Calm Fire', type: 'video', category: 'ambient', path: 'https://assets.mixkit.co/videos/25027/25027-720.mp4', preview: 'https://assets.mixkit.co/videos/25027/25027-720.mp4' },
            { id: 'hotlink_video_7', name: 'Library Hotlink', type: 'video', category: 'study', path: 'https://assets.mixkit.co/videos/15897/15897-720.mp4', preview: 'https://assets.mixkit.co/videos/15897/15897-720.mp4' },
            { id: 'hotlink_video_8', name: 'Beach Waves', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/5016/5016-720.mp4', preview: 'https://assets.mixkit.co/videos/5016/5016-720.mp4' },
            { id: 'hotlink_video_9', name: 'Clouds', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/2408/2408-720.mp4', preview: 'https://assets.mixkit.co/videos/2408/2408-720.mp4' },
            { id: 'hotlink_video_10', name: 'Sunset Sea', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/1926/1926-720.mp4', preview: 'https://assets.mixkit.co/videos/1926/1926-720.mp4' },
            { id: 'hotlink_video_11', name: 'Raft in River', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/1218/1218-720.mp4', preview: 'https://assets.mixkit.co/videos/1218/1218-720.mp4' },
            { id: 'hotlink_video_12', name: 'Rain in Lake', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/18312/18312-720.mp4', preview: 'https://assets.mixkit.co/videos/18312/18312-720.mp4' },
            { id: 'hotlink_video_13', name: 'Water on Leaf', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/ztlezxr73bgv1spkgnz6iv0ptc8s', preview: 'https://assets.mixkit.co/ztlezxr73bgv1spkgnz6iv0ptc8s' },
            { id: 'hotlink_video_14', name: 'Campfire', type: 'video', category: 'ambient', path: 'https://assets.mixkit.co/videos/47818/47818-720.mp4', preview: 'https://assets.mixkit.co/videos/47818/47818-720.mp4' },
            { id: 'hotlink_video_15', name: 'Wet Roses', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/ra8udcqr0qh570sq2b7m9zte5q20', preview: 'https://assets.mixkit.co/ra8udcqr0qh570sq2b7m9zte5q20' },
            { id: 'hotlink_video_16', name: 'Tranquil Forest', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/50847/50847-720.mp4', preview: 'https://assets.mixkit.co/videos/50847/50847-720.mp4' },
            { id: 'hotlink_video_17', name: 'Snowy Mountains', type: 'video', category: 'nature', path: 'https://assets.mixkit.co/videos/3371/3371-720.mp4', preview: 'https://assets.mixkit.co/videos/3371/3371-720.mp4' },
            { id: 'hotlink_video_18', name: 'Moon', type: 'video', category: 'ambient', path: 'https://assets.mixkit.co/videos/46898/46898-720.mp4', preview: 'https://assets.mixkit.co/videos/46898/46898-720.mp4' },
            { id: 'hotlink_video_19', name: 'Starry Sky Hotlink', type: 'video', category: 'ambient', path: 'https://assets.mixkit.co/videos/46119/46119-720.mp4', preview: 'https://assets.mixkit.co/videos/46119/46119-720.mp4' },
            { id: 'hotlink_video_20', name: 'Earth Spinning', type: 'video', category: 'abstract', path: 'https://assets.mixkit.co/videos/29351/29351-720.mp4', preview: 'https://assets.mixkit.co/videos/29351/29351-720.mp4' },
            { id: 'hotlink_video_21', name: 'Girl in Library', type: 'video', category: 'study', path: 'https://assets.mixkit.co/videos/4531/4531-720.mp4', preview: 'https://assets.mixkit.co/videos/4531/4531-720.mp4' },
            { id: 'hotlink_video_22', name: 'Cafe Hotlink', type: 'video', category: 'cafe', path: 'https://assets.mixkit.co/videos/29050/29050-720.mp4', preview: 'https://assets.mixkit.co/videos/29050/29050-720.mp4' },
            // Local Images (Restored)
            { id: 'image1', name: 'Starry Night', type: 'image', category: 'nature', path: '/static/assets/images/starry_night.jpg', preview: '/static/assets/images/starry_night.jpg' },
            { id: 'image2', name: 'Ocean Waves', type: 'image', category: 'nature', path: '/static/assets/images/ocean_waves.jpg', preview: '/static/assets/images/ocean_waves.jpg' },
            { id: 'image3', name: 'Cozy Cafe', type: 'image', category: 'cafe', path: '/static/assets/images/cozy_cafe.jpg', preview: '/static/assets/images/cozy_cafe.jpg' },
            { id: 'image4', name: 'Night City', type: 'image', category: 'city', path: '/static/assets/images/night_city.jpg', preview: '/static/assets/images/night_city.jpg' },
            { id: 'image5', name: 'Minimalist Desk', type: 'image', category: 'study', path: '/static/assets/images/minimalist_desk.jpg', preview: '/static/assets/images/minimalist_desk.jpg' },
            { id: 'image6', name: 'Bookshelf', type: 'image', category: 'study', path: '/static/assets/images/bookshelf.jpg', preview: '/static/assets/images/bookshelf.jpg' },
            { id: 'image7', name: 'Coffee & Notebook', type: 'image', category: 'cafe', path: '/static/assets/images/coffee_notebook.jpg', preview: '/static/assets/images/coffee_notebook.jpg' },
            { id: 'image8', name: 'Abstract Gradient', type: 'image', category: 'abstract', path: '/static/assets/images/abstract_gradient.jpg', preview: '/static/assets/images/abstract_gradient.jpg' },
            { id: 'image9', name: 'Boy', type: 'image', category: 'people', path: '/static/assets/images/boy.jpg', preview: '/static/assets/images/boy.jpg' },
            { id: 'image10', name: 'Bridge', type: 'image', category: 'nature', path: '/static/assets/images/bridge.jpg', preview: '/static/assets/images/bridge.jpg' },
            { id: 'image11', name: 'Flower in Hand', type: 'image', category: 'nature', path: '/static/assets/images/flower_in_hand.jpg', preview: '/static/assets/images/flower_in_hand.jpg' },
            { id: 'image12', name: 'Girl in Subway', type: 'image', category: 'city', path: '/static/assets/images/girl_in_subway.jpg', preview: '/static/assets/images/girl_in_subway.jpg' },
            { id: 'image13', name: 'Hibiscus', type: 'image', category: 'nature', path: '/static/assets/images/hibiscus.png', preview: '/static/assets/images/hibiscus.png' },
            { id: 'image14', name: 'Life is Beautiful', type: 'image', category: 'abstract', path: '/static/assets/images/life_is_beautiful.jpg', preview: '/static/assets/images/life_is_beautiful.jpg' },
            { id: 'image15', name: 'Pine', type: 'image', category: 'nature', path: '/static/assets/images/pine.jpg', preview: '/static/assets/images/pine.jpg' },
        ];

        const backgroundCategories = [
            { id: 'all', name: 'All', icon: 'fas fa-th' },
            { id: 'nature', name: 'Nature', icon: 'fas fa-leaf' },
            { id: 'cafe', name: 'Cafe', icon: 'fas fa-coffee' },
            { id: 'city', name: 'City', icon: 'fas fa-city' },
            { id: 'study', name: 'Study', icon: 'fas fa-book-open' },
            { id: 'ambient', name: 'Ambient', icon: 'fas fa-wind' },
            { id: 'abstract', name: 'Abstract', icon: 'fas fa-draw-polygon' },
            { id: 'people', name: 'People', icon: 'fas fa-user' },
        ];

        let currentSelectedBackgroundId = 'video1'; // Default restored to first local video
        let activeBgModalMainTab = 'video'; // 'video' or 'image'
        let activeBgModalSubCategory = 'all'; // e.g., 'all', 'nature', 'cafe'

        const $backgroundModal = $('#background-selection-modal');
        const $openBackgroundModalBtn = $('#open-background-modal-btn');
        const $closeBackgroundModalBtn = $('#close-background-modal-btn');
        const $currentBgNameDisplay = $('#current-background-name-display');
        const $bgModalMainTabs = $('.bg-modal-main-tab');
        const $bgModalSubCategoryTabsContainer = $('#bg-modal-subcategory-tabs');
        const $bgModalGridContainer = $('#bg-modal-grid-container');
        const $pageBackgroundContainer = $("#background-container"); // Renamed for clarity from $backgroundContainer

        // Function to render sub-category tabs in the background modal
        function renderBgModalSubCategoryTabs() {
            const $container = $('#bg-modal-subcategory-tabs');
            $container.empty(); // Clear existing tabs

            // Add 'All' tab first
            const $allTab = $(`
                <button class="bg-modal-subcategory-tab p-2 rounded-md text-gray-400 hover:text-purple-300 hover:bg-gray-700" title="All" data-category="all">
                    <i class="fas fa-th fa-lg"></i>
                </button>
            `);
            $container.append($allTab);

            const currentMainType = activeBgModalMainTab; // 'video' or 'image'
            let categoriesToShow = new Set();

            backgroundOptions.forEach(option => {
                if (option.type === currentMainType && option.category) {
                    categoriesToShow.add(option.category);
                }
            });

            // Sort categories alphabetically for consistent order
            const sortedCategories = Array.from(categoriesToShow).sort();

            sortedCategories.forEach(categoryKey => {
                const categoryDetails = backgroundCategories[categoryKey];
                if (categoryDetails) {
                    const $tab = $(`
                        <button class="bg-modal-subcategory-tab p-2 rounded-md text-gray-400 hover:text-purple-300 hover:bg-gray-700" title="${categoryDetails.name}" data-category="${categoryKey}">
                            <i class="${categoryDetails.icon} fa-lg"></i>
                        </button>
                    `);
                    $container.append($tab);
                }
            });

            // Set initial active sub-category tab
            $container.find(`[data-category="${activeBgModalSubCategory || 'all'}"]`).addClass('active');
        }
        window.renderBgModalSubCategoryTabs = renderBgModalSubCategoryTabs; // Expose to global scope

        // Function to render the grid of background items in the modal
        function renderBgModalGrid() {
            const $gridContainer = $('#bg-modal-grid-container');
            $gridContainer.empty();
            const currentMainType = activeBgModalMainTab; // 'video' or 'image'
            const currentSubCategory = activeBgModalSubCategory; // e.g., 'nature', 'city', or 'all'

            const filteredOptions = backgroundOptions.filter(option => {
                return option.type === currentMainType &&
                       (currentSubCategory === 'all' || !currentSubCategory || option.category === currentSubCategory);
            });

            if (filteredOptions.length === 0) {
                $gridContainer.html('<p class="col-span-full text-center text-gray-400 py-4">No backgrounds found for this category.</p>');
                return;
            }

            filteredOptions.forEach(option => {
                const isSelected = option.id === currentSelectedBackgroundId; // Use currentSelectedBackgroundId
                const $itemCard = $(`
                    <div class="background-item-card ${isSelected ? 'selected' : ''}" data-id="${option.id}" role="button" tabindex="0">
                        ${option.type === 'video' ? `
                            <video muted preload="metadata" class="background-item-preview" src="${option.preview || option.path}#t=0.1" onerror="handleMediaError(this, '${option.name}')"></video>
                        ` : `
                            <img class="background-item-preview" src="${option.preview || option.path}" alt="${option.name} preview" onerror="handleMediaError(this, '${option.name}')">
                        `}
                        <span class="background-item-name">${option.name}</span>
                    </div>
                `);
                $gridContainer.append($itemCard);
            });
        }
        window.renderBgModalGrid = renderBgModalGrid; // Expose to global scope

        function applyPageBackground(selectionId) {
            const selection = backgroundOptions.find(opt => opt.id === selectionId);
            if (!selection) return;

            $pageBackgroundContainer.empty();
            $pageBackgroundContainer.append('<div class="overlay"></div>');

            if (selection.type === 'video') {
                $pageBackgroundContainer.append(`
                    <video id="background-video" autoplay loop muted class="w-full h-full object-cover">
                        <source src="${selection.path}" type="video/${selection.path.split('.').pop()}">
                        Your browser does not support the video tag.
                    </video>
                `);
                if (selection.playbackRate) {
                     setTimeout(function() {
                        const vid = document.getElementById('background-video');
                        if (vid) vid.playbackRate = selection.playbackRate;
                    }, 100);
                }
            } else if (selection.type === 'image') {
                 $pageBackgroundContainer.append(`
                    <img id="background-image" src="${selection.path}" class="w-full h-full object-cover">
                `);
            }
            localStorage.setItem('selectedBackgroundId', selectionId);
        }

        // Modal open/close
        $(document).on('click', '#open-background-modal-btn', function(event) {
            console.log('[script.js] Delegated click for #open-background-modal-btn fired!');
            console.log('[script.js] Event target:', event.target);
            
            const $modal = $('#background-selection-modal'); // Re-select here
            console.log('[script.js] $modal (re-selected) found:', $modal.length);

            if ($modal.length) {
                console.log('[script.js] $modal initial display style (computed):', $modal.css('display'));
                console.log('[script.js] $modal classes BEFORE change:', $modal.attr('class'));
                
                $modal.removeClass('hidden'); // Show modal by removing 'hidden' class
                
                console.log('[script.js] $modal display style AFTER removeClass (computed):', $modal.css('display'));
                console.log('[script.js] $modal classes AFTER change:', $modal.attr('class'));

                // Ensure tabs and grid are rendered correctly when modal opens
                renderBgModalSubCategoryTabs(); 
                renderBgModalGrid();          
                playSound("sound-click");
            } else {
                console.error('[script.js] #background-selection-modal NOT FOUND in DOM when trying to open!');
            }
        });

        $(document).on('click', '#close-background-modal-btn', function() {
            const $modal = $('#background-selection-modal'); // Re-select here
            if ($modal.length) {
                console.log('[script.js] Close button clicked. Adding hidden class.');
                $modal.addClass('hidden'); // Hide modal by adding 'hidden' class
                playSound("sound-click");
            } else {
                console.error('[script.js] #background-selection-modal NOT FOUND in DOM when trying to close via button!');
            }
        });

        $(document).on('click', '#background-selection-modal', function(e) { // Close on backdrop click
            const $modal = $(this); 
            if (e.target === $modal[0]) { 
                console.log('[script.js] Backdrop clicked. Adding hidden class.');
                $modal.addClass('hidden'); // Hide modal
            }
        });

        // Main tabs for background type (Video/Image)
        $bgModalMainTabs.click(function() {
            activeBgModalMainTab = $(this).data('tab-type');
            $bgModalMainTabs.removeClass('active');
            $(this).addClass('active');
            activeBgModalSubCategory = 'all'; // Reset to 'all' when main tab changes
            renderBgModalSubCategoryTabs();
            renderBgModalGrid();
            playSound("sound-click");
        });

        // Initial render and setup for background
        const savedBgId = localStorage.getItem('selectedBackgroundId');
        if (savedBgId && backgroundOptions.find(opt => opt.id === savedBgId)) {
            currentSelectedBackgroundId = savedBgId;
        } else {
            // Ensure currentSelectedBackgroundId has a valid default if nothing is in localStorage
            currentSelectedBackgroundId = backgroundOptions.length > 0 ? backgroundOptions[0].id : null;
        }
        applyPageBackground(currentSelectedBackgroundId); 
        const initialSelectedOption = backgroundOptions.find(opt => opt.id === currentSelectedBackgroundId);
        if (initialSelectedOption) {
             $currentBgNameDisplay.text(initialSelectedOption.name);
        }
        // Initial state for modal tabs (won't be visible until opened, but good to set up)
        renderBgModalSubCategoryTabs(); 
        // renderBgModalGrid(); // Grid will render when modal opens
        

        // Old background select logic (Removed as per new design)
        /*
        const $backgroundGridContainer = $('#background-grid-container'); // This was the old simple grid
        const $changeBackgroundBtn = $('#change-background-btn'); // This was the old button toggling the simple grid
        function renderBackgroundGrid() { ... old simple grid logic ... }
        $changeBackgroundBtn.click(function() { ... old simple grid toggle ... });
        renderBackgroundGrid(); // Old simple grid population
        */
        
        // Ambient sound selection
        $("#ambient-sound-select").change(function() {
            const selection = $(this).val();
            
            // Stop all ambient sounds first
            $("#ambient-rain")[0].pause();
            $("#ambient-forest")[0].pause();
            $("#ambient-cafe")[0].pause();
            
            if (selection === "rain") {
                $("#ambient-rain")[0].play().catch(e => console.warn("Error playing sound:", e));
            } else if (selection === "forest") {
                $("#ambient-forest")[0].play().catch(e => console.warn("Error playing sound:", e));
            } else if (selection === "cafe") {
                $("#ambient-cafe")[0].play().catch(e => console.warn("Error playing sound:", e));
            }
            
            playSound("sound-click");
            
            if (selection !== "none") {
                // showNotification(`${$(this).find("option:selected").text()} sound enabled`, "info");
                showUIMessage("Environment", `${$(this).find("option:selected").text()} sound enabled.`, "info", true);
            } else {
                // showNotification("Ambient sound disabled", "info");
                showUIMessage("Environment", "Ambient sound disabled.", "info", true);
            }
        });
        
        // Volume control for ambient sounds
        $("#volume-slider").on("input", function() {
            const volume = $(this).val() / 100;
            $("#ambient-rain")[0].volume = volume;
            $("#ambient-forest")[0].volume = volume;
            $("#ambient-cafe")[0].volume = volume;
        });
        
        // Toggle sound on/off
        $("#sound-toggle").click(function() {
            const allAudio = $("audio");
            const isMuted = $(this).data("muted") || false;
            
            if (isMuted) {
                allAudio.prop("muted", false);
                $(this).data("muted", false);
                $(this).html('<i class="fas fa-volume-up"></i>');
                // showNotification("Sound enabled", "info");
                showUIMessage("Settings", "Sound enabled.", "info", true);
            } else {
                allAudio.prop("muted", true);
                $(this).data("muted", true);
                $(this).html('<i class="fas fa-volume-mute"></i>');
                // showNotification("Sound disabled", "info");
                showUIMessage("Settings", "Sound disabled.", "info", true);
            }
        });
        
        // Day/Night mode toggle
        $("#day-night-toggle").change(function() {
            if ($(this).is(":checked")) {
                $("body").addClass("night-mode");
                showUIMessage("Settings", "Night mode enabled.", "info", true);
            } else {
                $("body").removeClass("night-mode");
                showUIMessage("Settings", "Day mode enabled.", "info", true);
            }
            
            playSound("sound-click");
        });
        
        // Particles toggle
        $("#particles-toggle").change(function() {
            if ($(this).is(":checked")) {
                $("#particles-js").show();
                showUIMessage("Settings", "Particles enabled.", "info", true);
            } else {
                $("#particles-js").hide();
                showUIMessage("Settings", "Particles disabled.", "info", true);
            }
            
            playSound("sound-click");
        });
        
        // Initialize timer display
        updateTimerDisplay();
        
        // Load saved user data if available
        // loadUserData(); // We will call this after Firebase auth
        
        // Save user data every minute
        // setInterval(saveUserData, 60000); // Auto-save is fine, but session completion is key
        
        async function loadUserDataAndInitNotifications() {
            try {
                console.log("[Main Interface] Waiting for Firebase Auth to be ready...");
                const firebaseUser = await window.firebaseAuthReady; // Wait for Firebase Auth
                console.log("[Main Interface] Firebase Auth ready. Firebase User:", firebaseUser ? firebaseUser.uid : "null");

                const response = await fetch('/api/user_data');
                if (!response.ok) {
                    throw new Error('Failed to load user data from API');
                }
                
                const userDataFromAPI = await response.json();
                if (userDataFromAPI.error) {
                    console.error("[Main Interface] Error fetching user data from API:", userDataFromAPI.error);
                    showUIMessage("User Data", "Error: Could not load your user details.", "error", false); // Keep as local toast
                    return; // Stop if API user data fails
                }

                const apiUserId = userDataFromAPI.username; // This should be Firebase UID
                const displayUsername = userDataFromAPI.display_username || apiUserId || 'User';
                console.log(`[Main Interface] API UserID: ${apiUserId}, Display Name: ${displayUsername}`);

                // Store gamification settings globally
                if (userDataFromAPI.gamification_settings) {
                    gamificationSettings.badges = userDataFromAPI.gamification_settings.badges || {};
                    gamificationSettings.quests = userDataFromAPI.gamification_settings.quests || {};
                    gamificationSettings.leveling = userDataFromAPI.gamification_settings.leveling || { baseXpForLevelUp: 100 }; 
                    console.log("[Main Interface] Gamification settings loaded:", JSON.parse(JSON.stringify(gamificationSettings)));
                } else {
                    console.warn("[Main Interface] No gamification_settings received from API.");
                }
                
                // Update UI with userDataFromAPI.progress
                if (userDataFromAPI.progress) {
                    currentUserProgress = userDataFromAPI.progress; // Store current progress
                    updateProgressUI(currentUserProgress); // New function to update all progress UI
                }


                // Now initialize the global notification system
                if (firebaseUser && firebaseUser.uid === apiUserId) {
                    console.log(`[Main Interface] Firebase Auth Confirmed: UID ${firebaseUser.uid} matches API UserID ${apiUserId}. Attempting to initialize notifications...`);
                    if (typeof initializeGlobalNotificationSystem === 'function') {
                        initializeGlobalNotificationSystem(firebaseUser.uid); // Initialize with actual Firebase UID
                        console.log("[Main Interface] Called initializeGlobalNotificationSystem.");

                        // Add a welcome notification if it's the main page, for example
                         console.log("[Main Interface] Checking for 'mainPageWelcomeNotificationSent' in sessionStorage. Value:", sessionStorage.getItem('mainPageWelcomeNotificationSent'));
                         if (!sessionStorage.getItem('mainPageWelcomeNotificationSent')) {
                             console.log("[Main Interface] 'mainPageWelcomeNotificationSent' NOT found in sessionStorage. Proceeding to add Welcome Back notification.");
                             console.log("[Main Interface] Checking if typeof addNotification === 'function'. Is it?", typeof addNotification === 'function');
                             if (typeof addNotification === 'function') { // This is the global addNotification from notifications.js
                                 console.log(`[Main Interface] Attempting to call addNotification for Welcome Back. Display name: ${displayUsername}`);
                                 addNotification('Welcome Back!', `Hello ${displayUsername}, ready for a productive session?`, 'success');
                                 console.log("[Main Interface] addNotification for Welcome Back CALLED.");
                             } else {
                                 console.error("[Main Interface] addNotification function is NOT defined when trying to send Welcome Back message.");
                             }
                             sessionStorage.setItem('mainPageWelcomeNotificationSent', 'true');
                             console.log("[Main Interface] 'mainPageWelcomeNotificationSent' SET in sessionStorage.");
                         } else {
                             console.log("[Main Interface] 'mainPageWelcomeNotificationSent' IS found in sessionStorage. Skipping Welcome Back notification.");
                         }

                    } else {
                        console.error("[Main Interface] initializeGlobalNotificationSystem is not defined. CRITICAL: Ensure notifications.js is loaded.");
                        showUIMessage("System Error", "Notification system error.", "error", false); // Keep as local toast
                    }
                } else {
                     if (!firebaseUser) {
                        console.warn(`[Main Interface] Firebase user is NULL when trying to set up for API UserID: ${apiUserId}. Global notifications likely disabled.`);
                        showUIMessage("Auth Error", "Client not signed into Firebase. Global notifications may not work.", "error", false); // Keep as local toast
                    } else { // firebaseUser.uid !== apiUserId
                        console.error(`[Main Interface] CRITICAL UID MISMATCH on main page: API UserID is ${apiUserId}, but Firebase Auth UID is ${firebaseUser.uid}. Global notifications disabled.`);
                        showUIMessage("Auth Error", "User identity mismatch. Please re-login. Global notifications disabled.", "error", false); // Keep as local toast
                    }
                }

            } catch (error) {
                console.error("[Main Interface] Error in loadUserDataAndInitNotifications:", error);
                showUIMessage("System Error", "Error loading user data or initializing notifications.", "error", false); // Keep as local toast
            }
        }
        
        // Call the new function that handles both user data loading and notification init
        // This call is typically done in $(document).ready() after this function definition.
        // loadUserDataAndInitNotifications(); // Ensure this is called in doc ready
        
        function renderGamificationGuide() {
            console.log("[renderGamificationGuide] Called.");
            if (!gamificationSettings || !currentUserProgress) {
                console.warn("[renderGamificationGuide] Gamification settings or user progress not yet loaded. Guide cannot be rendered.");
                return;
            }
            // More detailed logging here
            console.log("[renderGamificationGuide] gamificationSettings.badges available:", gamificationSettings.badges ? Object.keys(gamificationSettings.badges).length + " entries" : "undefined/null");
            console.log("[renderGamificationGuide] gamificationSettings.badges content:", JSON.stringify(gamificationSettings.badges));

            console.log("[renderGamificationGuide] gamificationSettings.quests available:", gamificationSettings.quests ? "Object found" : "undefined/null");
            if (gamificationSettings.quests) {
                console.log("[renderGamificationGuide] gamificationSettings.quests has 'daily' key:", gamificationSettings.quests.hasOwnProperty('daily'));
                console.log("[renderGamificationGuide] gamificationSettings.quests has 'weekly' key:", gamificationSettings.quests.hasOwnProperty('weekly'));
                if (gamificationSettings.quests.daily) {
                    console.log("[renderGamificationGuide] gamificationSettings.quests.daily count:", gamificationSettings.quests.daily.length);
                } else {
                    console.log("[renderGamificationGuide] gamificationSettings.quests.daily is undefined or null");
                }
                if (gamificationSettings.quests.weekly) {
                    console.log("[renderGamificationGuide] gamificationSettings.quests.weekly count:", gamificationSettings.quests.weekly.length);
                } else {
                    console.log("[renderGamificationGuide] gamificationSettings.quests.weekly is undefined or null");
                }
            }
            console.log("[renderGamificationGuide] gamificationSettings.quests content:", JSON.stringify(gamificationSettings.quests));


            console.log("[renderGamificationGuide] currentUserProgress.badges available:", currentUserProgress.badges ? currentUserProgress.badges.length + " entries" : "undefined/null/empty array");
            console.log("[renderGamificationGuide] currentUserProgress.badges content:", JSON.stringify(currentUserProgress.badges));
            
            renderAllBadgesGuide(gamificationSettings.badges || {}, currentUserProgress.badges || []);
            renderAllQuestTypesGuide(gamificationSettings.quests || {});
        }

        function renderAllBadgesGuide(allBadgeDefs, userEarnedBadgeIds) {
            console.log("[renderAllBadgesGuide] Received allBadgeDefs:", JSON.parse(JSON.stringify(allBadgeDefs)), "userEarnedBadgeIds:", userEarnedBadgeIds);
            const $badgeListContainer = $("#guide-badges-list");
            const $noDefsMessage = $("#no-badge-definitions-message");
            $badgeListContainer.empty(); // Clear previous badges

            if (Object.keys(allBadgeDefs).length === 0) {
                $noDefsMessage.removeClass("hidden");
                return;
            }
            $noDefsMessage.addClass("hidden");

            const earnedIdsSet = new Set(userEarnedBadgeIds || []);

            for (const badgeId in allBadgeDefs) {
                const badgeDef = allBadgeDefs[badgeId];
                const isEarned = earnedIdsSet.has(badgeId);

                const criteriaText = badgeDef.criteria_text || badgeDef.description || "Criteria not specified.";

                const badgeCardHtml = `
                    <div class="guide-badge-card ${isEarned ? 'earned' : 'unearned'}">
                        <div class="badge-icon-container" style="background-color: ${isEarned ? (badgeDef.color || '#777') : 'transparent'};">
                            <i class="fas ${badgeDef.icon || 'fa-question-circle'} fa-fw" style="color: ${isEarned ? (badgeDef.textColor || 'white') : '#9ca3af'};"></i>
                        </div>
                        <p class="badge-name">${badgeDef.name || "Unnamed Badge"}</p>
                        <p class="badge-description">${badgeDef.description || "No description."}</p>
                        <p class="badge-criteria">How to earn: ${criteriaText}</p>
                    </div>
                `;
                $badgeListContainer.append(badgeCardHtml);
            }
        }

        function renderAllQuestTypesGuide(allQuestTypeDefs) {
            console.log("[renderAllQuestTypesGuide] Received allQuestTypeDefs:", JSON.parse(JSON.stringify(allQuestTypeDefs)));
            const $dailyListContainer = $("#guide-daily-quests-list .space-y-3");
            const $weeklyListContainer = $("#guide-weekly-quests-list .space-y-3");
            const $noDailyMessage = $("#no-daily-quest-definitions-message");
            const $noWeeklyMessage = $("#no-weekly-quest-definitions-message");

            $dailyListContainer.empty();
            $weeklyListContainer.empty();

            if (allQuestTypeDefs.daily && allQuestTypeDefs.daily.length > 0) {
                $noDailyMessage.addClass("hidden");
                allQuestTypeDefs.daily.forEach(template => {
                    const descExample = template.descriptionTemplate.replace("{N}", "(e.g., " + template.targetMin + "-" + template.targetMax + ")");
                    const questCardHtml = `
                        <div class="guide-quest-card">
                            <h5 class="quest-title flex items-center"><i class="fas ${template.icon || 'fa-clipboard-list'} fa-fw mr-2"></i>${template.title}</h5>
                            <p class="quest-description-template">${descExample}</p>
                            <p class="quest-details">Goal Type: ${template.goalType} | Reward: ~${template.rewardXp} XP</p>
                        </div>
                    `;
                    $dailyListContainer.append(questCardHtml);
                });
            } else {
                $noDailyMessage.removeClass("hidden");
            }

            if (allQuestTypeDefs.weekly && allQuestTypeDefs.weekly.length > 0) {
                $noWeeklyMessage.addClass("hidden");
                allQuestTypeDefs.weekly.forEach(template => {
                    const descExample = template.descriptionTemplate.replace("{N}", "(e.g., " + template.targetMin + "-" + template.targetMax + ")");
                    const questCardHtml = `
                        <div class="guide-quest-card">
                            <h5 class="quest-title flex items-center"><i class="fas ${template.icon || 'fa-calendar-alt'} fa-fw mr-2"></i>${template.title}</h5>
                            <p class="quest-description-template">${descExample}</p>
                            <p class="quest-details">Goal Type: ${template.goalType} | Reward: ~${template.rewardXp} XP</p>
                        </div>
                    `;
                    $weeklyListContainer.append(questCardHtml);
                });
            } else {
                $noWeeklyMessage.removeClass("hidden");
            }
        }

        function updateProgressUI(progressData) {
            if (!progressData) {
                console.warn("updateProgressUI called with no progressData");
                return;
            }
            console.log("Updating UI with progress data:", progressData);

            const currentLevel = progressData.level || 1;
            const xpNeededForNextLevel = (gamificationSettings.leveling?.baseXpForLevelUp || 100) * currentLevel;

            $("#level").text(currentLevel);
            const inLevelXp = progressData.xp || 0;
            const totalXpVal = progressData.totalXp || inLevelXp;

            $("#xp").text(inLevelXp);
            $("#xp-needed").text(xpNeededForNextLevel);
            
            $("#total-time").text(progressData.total_time || 0);
            $("#streak").text(progressData.streak || 0);
            
            const progressPercentage = xpNeededForNextLevel > 0 ? ((progressData.xp || 0) / xpNeededForNextLevel) * 100 : 0;
            
            $("#stats-total-time").text((progressData.total_time || 0) + " min");
            $("#stats-total-sessions").text(progressData.sessions || 0);
            
            // NEW: Update consolidated Stats panel elements
            $("#stats-level").text(currentLevel);
            $("#stats-xp").text(inLevelXp);
            $("#stats-xp-needed").text(xpNeededForNextLevel);
            $("#stats-streak").text((progressData.streak || 0) + " days");
            $("#stats-xp-progress").css("width", Math.min(100, progressPercentage) + "%");
            // Keep total time and sessions already updated above for Stats panel
            
            $("#xp-progress").css("width", Math.min(100, progressPercentage) + "%"); // Cap at 100%
            
            renderBadges(progressData.badges || [], gamificationSettings.badges || {});
            renderQuests(progressData.activeQuests || [], gamificationSettings.quests || {});

            // Render session history from server data
            $("#recent-sessions").empty();
            if (progressData.sessionHistory && progressData.sessionHistory.length > 0) {
                const sortedHistory = [...progressData.sessionHistory].sort((a, b) => new Date(b.date) - new Date(a.date));
                sortedHistory.slice(0, 10).forEach(session => { // Display last 10
                    const date = new Date(session.date);
                    const displayDateStr = date.toLocaleDateString();
                    const displayTimeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    const sessionEntryHTML = $(`
                        <div class="session-entry bg-gray-700 bg-opacity-50 p-2 rounded mb-2 flex justify-between items-center" data-timestamp="${session.date}">
                            <div>
                                <span class="text-xs text-gray-400">${displayDateStr} at ${displayTimeStr}</span>
                                <p class="text-sm">${session.duration} min ${session.type} session</p>
                            </div>
                            <div class="text-purple-300"><i class="fas fa-check-circle"></i></div>
                        </div>
                    `);
                    $("#recent-sessions").append(sessionEntryHTML);
                });
            } else {
                $("#recent-sessions").html('<p class="text-gray-400 text-center">No sessions recorded yet.</p>');
            }
        }

        function renderBadges(userBadgeIds, badgeDefinitionsFromServer) {
            // Support duplicate IDs (hidden Progress panel + visible Stats panel)
            // jQuery's #selector returns only the first element when IDs are duplicated, so we
            // explicitly fetch the instance that lives under #stats-panel as well.
            const $badgesContainers = $("#badges-list, #stats-panel #badges-list");
            const $noBadgeMessages = $("#no-badges-message, #stats-panel #no-badges-message");

            $badgesContainers.empty();

            let awardedCount = 0;
            const badgeDefsToUse = badgeDefinitionsFromServer || gamificationSettings.badges || {};

            if (userBadgeIds && userBadgeIds.length > 0 && Object.keys(badgeDefsToUse).length > 0) {
                userBadgeIds.forEach(badgeId => {
                    const badgeDef = badgeDefsToUse[badgeId];
                    if (badgeDef) {
                        const badgeHtml = `
                            <div id="badge-${badgeId}" class="badge tooltip shadow-md" style="background: ${badgeDef.color || '#777'}; color: ${badgeDef.textColor || 'white'}" title="${badgeDef.name} - ${badgeDef.description}">
                                <i class="fas ${badgeDef.icon || 'fa-medal'}"></i>
                                <span class="tooltiptext">${badgeDef.name}: ${badgeDef.description}</span>
                            </div>`;
                        // Append the badge to EACH container so both panels stay in sync
                        $badgesContainers.each(function() {
                            $(this).append(badgeHtml);
                        });
                        awardedCount++;
                    }
                });
            }

            if (awardedCount === 0) {
                $noBadgeMessages.removeClass("hidden");
            } else {
                $noBadgeMessages.addClass("hidden");
            }

            // Update count if Stats card exists
            $("#stats-total-badges").text(awardedCount);
        }

        function renderQuests(activeQuests, questDefinitionsFromServer) {
            const $questsList = $("#active-quests-list");
            $questsList.empty();
            const questDefsToUse = questDefinitionsFromServer || gamificationSettings.quests || {};

            if (activeQuests && activeQuests.length > 0 && (questDefsToUse.daily || questDefsToUse.weekly)) {
                 $("#no-quests-message").addClass("hidden");
                activeQuests.forEach(quest => {
                    const template = questDefsToUse.daily?.[quest.templateId] || questDefsToUse.weekly?.[quest.templateId];
                    if (template) {
                        const progressPercentage = quest.goal > 0 ? Math.min(100, (quest.currentProgress / quest.goal) * 100) : 0;
                        const questHtml = `
                            <div class="quest-item bg-gray-700 bg-opacity-70 p-3 rounded-lg shadow-sm">
                                <div class="flex justify-between items-center mb-1">
                                    <h4 class="font-semibold text-sm text-purple-300">${quest.title}</h4>
                                    ${!quest.completed ? `<span class="text-xs text-gray-400">${quest.currentProgress} / ${quest.goal}</span>` : ''}
                                </div>
                                <p class="text-xs text-gray-300 mb-2">${quest.description}</p>
                                ${!quest.completed ? `
                                <div class="w-full bg-gray-600 rounded-full h-1.5">
                                    <div class="bg-gradient-to-r from-green-400 to-blue-500 h-1.5 rounded-full transition-all duration-500 ease-out" style="width: ${progressPercentage}%"></div>
                                </div>
                                ` : `
                                <div class="text-xs text-green-400 mt-1 font-semibold flex items-center">
                                    <i class="fas fa-check-circle mr-1"></i> Completed! +${template.rewardXp || '??'} XP
                                </div>`}
                            </div>
                        `;
                        $questsList.append(questHtml);
                    }
                });
            } else {
                $("#no-quests-message").removeClass("hidden");
            }
        }
        
        async function loadUserData() {
            console.warn("[Main Interface] loadUserData() was called, but logic is now in loadUserDataAndInitNotifications(). Triggering it.");
            await loadUserDataAndInitNotifications();
        }
        
        async function saveUserData(eventDetails = null) {
            try {
                let clientPayload = {
                    progress: { // Always send current core progress for potential merge on server
                        xp: parseInt($("#xp").text()) || 0,
                        level: parseInt($("#level").text()) || 1,
                        total_time: parseInt($("#total-time").text()) || 0,
                        sessions: parseInt($("#stats-total-sessions").text()) || 0,
                        // sessionHistory is now primarily managed by server based on events, 
                        // but we can send the client's current known history for non-event syncs.
                        sessionHistory: currentUserProgress.sessionHistory || [] 
                    }
                };

                if (eventDetails && eventDetails.event_type) {
                    clientPayload.event_type = eventDetails.event_type;
                    clientPayload.event_data = eventDetails.event_data || {};
                }
                
                console.log("Saving user data with payload:", JSON.stringify(clientPayload, null, 2));
                
                const response = await fetch('/api/user_data', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(clientPayload)
                });
                
                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Failed to save user data. Status: ${response.status}. Server: ${errorText}`);
                }

                const result = await response.json();
                if (result.error) {
                    throw new Error('Error from server saving user data: ' + result.error);
                }

                if (result.status === 'success') {
                    console.log("User data saved/processed successfully. Server response:", result);
                    if (result.progress) {
                        currentUserProgress = result.progress; // Update global state
                        updateProgressUI(currentUserProgress); // Refresh UI with server's authoritative state
                    }

                    // Handle notifications for gamification events from server response
                    if (result.new_badges && result.new_badges.length > 0) {
                        result.new_badges.forEach(badgeId => {
                            const badgeDef = gamificationSettings.badges?.[badgeId];
                            if (badgeDef) {
                                showUIMessage("Badge Unlocked!", `You've earned the \\"${badgeDef.name}\\" badge! (${badgeDef.description})`, "success", true);
                                playSound("sound-levelup");
                                createConfetti();
                            }
                        });
                    }
                    if (result.leveled_up_to) {
                        showUIMessage("Level Up!", `Congratulations! You've reached Level ${result.leveled_up_to}!`, "success", true);
                        playSound("sound-levelup");
                        createConfetti();
                    }
                    if (result.completed_quests && result.completed_quests.length > 0) {
                         result.completed_quests.forEach(questTitle => {
                            showUIMessage("Quest Completed!", `You've completed the quest: \\"${questTitle}\\"!`, "success", true);
                            // XP for quest is handled server-side and included in progress update. Sound/confetti might be desired here too.
                            playSound("sound-complete"); // Or a specific quest complete sound
                        });
                    }

                } else {
                    console.warn("User data save/process status not explicitly success:", result);
                }

            } catch (error) {
                console.error("Error saving user data:", error);
                showUIMessage("Save Error", "Could not save your progress: " + error.message, "error", false);
            }
        }

        // Set default ambient sound to rain and play it
        $("#ambient-sound-select").val("rain").trigger("change");

        function getDaphinixMemory() {
            // Returns an array of {role: 'user'|'assistant', content: '...'}
            const memory = JSON.parse(localStorage.getItem('daphinixMemory') || '[]');
            return memory;
        }

        function addToDaphinixMemory(role, content) {
            let memory = getDaphinixMemory();
            memory.push({ role, content });
            // Keep only the last 5 exchanges (10 messages)
            if (memory.length > 10) memory = memory.slice(memory.length - 10);
            localStorage.setItem('daphinixMemory', JSON.stringify(memory));
        }

        function clearDaphinixMemory() {
            localStorage.removeItem('daphinixMemory');
        }

        $(document).one('click', function() {
            if ($("#ambient-sound-select").val() === "rain") {
                $("#ambient-rain")[0].play().catch(e => {});
            }
        });

        // --- Enhanced To-Do List Feature ---
        async function loadTodoList() {
            try {
                const response = await fetch('/api/todo_list');
                if (!response.ok) {
                    throw new Error('Failed to load todo list');
                }
                
                const todos = await response.json();
                const tbody = $('#todo-table-body');
                tbody.empty();
                
                if (todos && todos.length > 0) {
                    todos.forEach(todo => {
                        const row = `
                            <tr data-task-id="${todo.timestamp}">
                                <td class="py-2 px-4">${todo.name}</td>
                                <td class="py-2 px-4">${new Date(todo.startDate).toLocaleString()}</td>
                                <td class="py-2 px-4">${new Date(todo.dueDate).toLocaleString()}</td>
                                <td class="py-2 px-4">
                                    <select class="todo-status bg-gray-800 text-white rounded px-2 py-1">
                                        <option value="Not started" ${todo.status === 'Not started' ? 'selected' : ''}>Not started</option>
                                        <option value="In progress" ${todo.status === 'In progress' ? 'selected' : ''}>In progress</option>
                                        <option value="Done" ${todo.status === 'Done' ? 'selected' : ''}>Done</option>
                                    </select>
                                    ${todo.completedAt ? `<br><small class="text-gray-400">Completed: ${new Date(todo.completedAt).toLocaleString()}</small>` : ''}
                                </td>
                                <td class="py-2 px-4">${todo.priority}</td>
                                <td class="py-2 px-4">${todo.effort}</td>
                                <td class="py-2 px-4">${todo.desc || ''}</td>
                                <td class="py-2 px-4">
                                    <button class="delete-todo text-red-500 hover:text-red-700">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </td>
                            </tr>
                        `;
                        tbody.append(row);
                    });
                } else {
                    tbody.append('<tr><td colspan="8" class="text-center py-4">No tasks found</td></tr>');
                }
            } catch (error) {
                console.error('Error loading todo list:', error);
                // showNotification('Error loading tasks. Please refresh the page.', 'error'); // Local toast
                showUIMessage('To-Do Error', 'Error loading tasks. Please refresh.', 'error', false);
            }
        }

        // Modal open/close logic
        $(document).on('click', '#open-todo-modal', function() {
            $('#todo-modal').removeClass('hidden').show();
        });
        $(document).on('click', '#close-todo-modal', function() {
            $('#todo-modal').addClass('hidden').hide();
            $('#todo-form')[0].reset();
        });

        // Add task logic
        $(document).on('submit', '#todo-form', async function(e) {
            e.preventDefault();
            const name = $('#todo-input-name').val().trim();
            const startDate = $('#todo-input-start').val();
            const dueDate = $('#todo-input-due').val();
            const status = $('#todo-input-status').val();
            const priority = $('#todo-input-priority').val();
            const effort = $('#todo-input-effort').val();
            const desc = $('#todo-input-desc').val().trim();
            
            if (name && startDate && dueDate) {
                try {
                    // Get current todo list
                    const response = await fetch('/api/todo_list');
                    const todos = await response.json();
                    
                    // Add new task with UTC timestamps
                    const task = {
                        name,
                        startDate: new Date(startDate).toISOString(),
                        dueDate: new Date(dueDate).toISOString(),
                        status,
                        priority,
                        effort,
                        desc,
                        timestamp: new Date().toISOString(),
                        completedAt: status === 'Done' ? new Date().toISOString() : null
                    };
                    
                    const updatedTodos = [...(todos || []), task];
                    
                    // Save updated todo list
                    const saveResponse = await fetch('/api/todo_list', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(updatedTodos)
                    });
                    
                    if (saveResponse.ok) {
                        await loadTodoList();
                        $('#todo-modal').addClass('hidden').hide();
                        $('#todo-form')[0].reset();
                        // showNotification('Task added!', 'success');
                        showUIMessage('To-Do', 'Task added!', 'success', true);
                    } else {
                        throw new Error('Failed to save task');
                    }
            } catch (error) {
                    console.error('Error:', error);
                    // showNotification('Error adding task. Please try again.', 'error'); // Local toast
                    showUIMessage('To-Do Error', 'Error adding task. Please try again.', 'error', false);
                }
            }
        });

        // Add status change handler
        $(document).on('change', '.todo-status', async function() {
            const taskId = $(this).closest('tr').data('task-id');
            const newStatus = $(this).val();
            
            try {
                const response = await fetch('/api/todo_list');
                const todos = await response.json();
                
                const updatedTodos = todos.map(todo => {
                    if (todo.timestamp === taskId) {
                        return {
                            ...todo,
                            status: newStatus,
                            completedAt: newStatus === 'Done' ? new Date().toISOString() : null
                        };
                    }
                    return todo;
                });
                
                const saveResponse = await fetch('/api/todo_list', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(updatedTodos)
                });
                
                if (saveResponse.ok) {
                    await loadTodoList();
                    // showNotification('Task status updated!', 'success');
                    showUIMessage('To-Do', 'Task status updated!', 'success', true);
                } else {
                    throw new Error('Failed to update task status');
                }
            } catch (error) {
                console.error('Error:', error);
                // showNotification('Error updating task status. Please try again.', 'error'); // Local toast
                showUIMessage('To-Do Error', 'Error updating task status. Please try again.', 'error', false);
            }
        });

        // Delete task logic
        $(document).on('click', '.delete-todo', async function() {
            const taskId = $(this).closest('tr').data('task-id');
            
            try {
                // Get current todo list
                const response = await fetch('/api/todo_list');
                const todos = await response.json();
                
                // Filter out the deleted task
                const updatedTodos = todos.filter(todo => todo.timestamp !== taskId);
                
                // Save updated todo list
                const saveResponse = await fetch('/api/todo_list', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(updatedTodos)
                });
                
                if (saveResponse.ok) {
                    await loadTodoList(); // Reload the todo list
                    // showNotification('Task deleted!', 'info');
                    showUIMessage('To-Do', 'Task deleted!', 'info', true);
                } else {
                    throw new Error('Failed to delete task');
                }
            } catch (error) {
                console.error('Error:', error);
                // showNotification('Error deleting task. Please try again.', 'error'); // Local toast
                showUIMessage('To-Do Error', 'Error deleting task. Please try again.', 'error', false);
            }
        });

        document.addEventListener('DOMContentLoaded', function() {
            loadTodoList();
            // Reminder check every minute
            setInterval(function() {
                const todoList = JSON.parse(localStorage.getItem('todoList') || '[]');
                const now = new Date();
                todoList.forEach((task, idx) => {
                    if (task.status !== 'Done' && task.dueDate) {
                        const due = new Date(task.dueDate);
                        if (now >= due && !task.reminded) {
                            // Play notification sound
                            playSound('sound-complete'); // This is a local sound, addNotification will play its own
                            // showNotification(`Task due: ${task.name}`, 'warning', 7000);
                            showUIMessage('To-Do Reminder', `Task due: ${task.name}`, 'warning', true);
                            // Mark as reminded
                            task.reminded = true;
                        }
                    }
                });
                localStorage.setItem('todoList', JSON.stringify(todoList));
            }, 60000);
        });

        // Load data when the page loads
        $(document).ready(function() {
            loadUserDataAndInitNotifications(); // Ensure this is called
            loadTodoList();
            loadChatHistory();
            fetchAndRenderLeaderboard('xp'); // Initial load with XP by default
            fetchAndDisplayInspireContent(); // Initial load for Inspire Me tab
        });

        // Save user data periodically (for non-event syncs if needed)
        // setInterval(() => saveUserData(), 120000); // Sync every 2 minutes
        // More controlled saves are better, e.g., on window unload or specific non-critical actions.
        window.addEventListener('beforeunload', () => saveUserData());


        // Event listener for leaderboard type change
        $(".leaderboard-filter-btn").click(function() {
            const $this = $(this);
            if ($this.hasClass('active')) return; // Already active

            $(".leaderboard-filter-btn").removeClass('active bg-purple-600 text-white').addClass('text-gray-300 hover:bg-gray-700');
            $this.removeClass('text-gray-300 hover:bg-gray-700').addClass('active bg-purple-600 text-white');
            
            const type = $this.data('type');
            fetchAndRenderLeaderboard(type);
        });

        async function fetchAndRenderLeaderboard(type) {
            // Support multiple leaderboard sections (Stats panel, standalone Leaderboard panel, etc.)
            const $tbodyAll        = $("#leaderboard-table-body, #stats-panel #leaderboard-table-body, #leaderboard-panel #leaderboard-table-body");
            const $loadingAll      = $("#leaderboard-loading, #stats-panel #leaderboard-loading, #leaderboard-panel #leaderboard-loading");
            const $errorAll        = $("#leaderboard-error, #stats-panel #leaderboard-error, #leaderboard-panel #leaderboard-error");
            const $noDataAll       = $("#no-leaderboard-data, #stats-panel #no-leaderboard-data, #leaderboard-panel #no-leaderboard-data");
 
            $tbodyAll.empty();
            $loadingAll.removeClass("hidden");
            $errorAll.addClass("hidden");
            $noDataAll.addClass("hidden");
 
            try {
                const leaderboardData = await loadLeaderboardData(type);
                if (leaderboardData && leaderboardData.length > 0) {
                    let currentUserData = null;
                    let currentUserRank = -1;

                    leaderboardData.forEach((entry, index) => {
                        if (entry.username === currentUserProgress.username) { // Assuming currentUserProgress.username is the unique ID
                            currentUserData = entry;
                            currentUserRank = entry.rank;
                        }
                    });

                    const displayEntries = [];
                    const addedUsernames = new Set();

                    // 1. Add Top 3
                    for (let i = 0; i < Math.min(3, leaderboardData.length); i++) {
                        displayEntries.push(leaderboardData[i]);
                        addedUsernames.add(leaderboardData[i].username);
                    }

                    // 2. Add Current User and Neighbors (if not already in top 3)
                    if (currentUserData && currentUserRank > 3) {
                        const userIndexInFetchedData = leaderboardData.findIndex(u => u.username === currentUserData.username);
                        if (userIndexInFetchedData !== -1) {
                            // Add a separator if there's a gap between top 3 and user's section
                            if (displayEntries.length > 0 && leaderboardData[userIndexInFetchedData-1] && 
                                !addedUsernames.has(leaderboardData[userIndexInFetchedData-1].username) && 
                                userIndexInFetchedData > displayEntries.length) { // Check if the preceding element is not the last of top 3
                                displayEntries.push({isSeparator: true});
                            }

                            // User -1 (if exists and not already added)
                            if (userIndexInFetchedData > 0 && !addedUsernames.has(leaderboardData[userIndexInFetchedData - 1].username)) {
                                displayEntries.push(leaderboardData[userIndexInFetchedData - 1]);
                                addedUsernames.add(leaderboardData[userIndexInFetchedData - 1].username);
                            }
                            // Current User (if not already added - should not happen if rank > 3)
                            if (!addedUsernames.has(currentUserData.username)){
                                displayEntries.push(currentUserData);
                                addedUsernames.add(currentUserData.username);
                            }
                            // User +1 (if exists and not already added)
                            if (userIndexInFetchedData < leaderboardData.length - 1 && !addedUsernames.has(leaderboardData[userIndexInFetchedData + 1].username)) {
                                displayEntries.push(leaderboardData[userIndexInFetchedData + 1]);
                                // addedUsernames.add(leaderboardData[userIndexInFetchedData + 1].username); // No need to add to set if it's the last one added in this block
                            }
                        }
                    } else if (currentUserData && currentUserRank <=3) {
                        // User is in top 3, already added. Do nothing special here.
                    } else if (!currentUserData && leaderboardData.length > 3) {
                         // User not in top 20, add a separator after top 3 if there are more entries.
                         displayEntries.push({isSeparator: true, customText: "Your rank is not in the top 20 for this board."})                    
                    }

                    displayEntries.forEach(entry => {
                        if (entry.isSeparator) {
                            const separatorText = entry.customText || "...";
                            const separatorRow = `
                                <tr>
                                    <td colspan="5" class="py-2 px-3 text-center text-gray-500 text-xs italic">${separatorText}</td>
                                </tr>
                            `;
                            $tbodyAll.append(separatorRow);
                            return;
                        }

                        let rankDisplay = entry.rank;
                        if (entry.rank === 1) rankDisplay = '🥇';
                        else if (entry.rank === 2) rankDisplay = '🥈';
                        else if (entry.rank === 3) rankDisplay = '🥉';
                        
                        const isCurrentUserEntry = entry.username === currentUserProgress.username;

                        const row = `
                            <tr class="text-sm ${isCurrentUserEntry ? 'bg-purple-700 bg-opacity-30 font-semibold' : 'hover:bg-gray-700 bg-opacity-50'} transition-colors">
                                <td class="py-2 px-3 border-b border-gray-700 text-center">${rankDisplay}</td>
                                <td class="py-2 px-3 border-b border-gray-700">${entry.username} ${isCurrentUserEntry ? '(You)' : ''}</td>
                                <td class="py-2 px-3 border-b border-gray-700 text-center">${entry.level}</td>
                                <td class="py-2 px-3 border-b border-gray-700 text-right">${entry.xp}</td>
                                <td class="py-2 px-3 border-b border-gray-700 text-center">${entry.streak}</td>
                            </tr>
                        `;
                        $tbodyAll.append(row);
                    });
                } else {
                    $noDataAll.removeClass("hidden");
                }
            } catch (err) {
                console.error("Error fetching leaderboard:", err);
                $errorAll.text("Error: " + err.message).removeClass("hidden");
            } finally {
                $loadingAll.addClass("hidden");
            }
        }

        // Initialize notification system
            const bell = document.getElementById('notification-bell');
            const panel = document.getElementById('notification-panel');
            
            if (bell && panel) {
                bell.addEventListener('click', function(e) {
                e.stopPropagation(); // Prevent click from bubbling to document
                    panel.classList.toggle('hidden');
                    if (!panel.classList.contains('hidden')) {
                        // markAllAsRead(); // OLD: Was local script.js notifications
                        if (typeof markAllCurrentUserNotificationsAsRead === 'function') {
                            markAllCurrentUserNotificationsAsRead();
                            console.log("[Main Interface] Called global markAllCurrentUserNotificationsAsRead.");
                        } else {
                            console.error("[Main Interface] markAllCurrentUserNotificationsAsRead is not defined.");
                        }
                    }
                });
                
            // Clear notifications button specific to this panel
                const clearBtn = document.getElementById('clear-notifications');
                if (clearBtn) {
                    clearBtn.addEventListener('click', function(e) {
                    e.stopPropagation(); // Prevent click from bubbling to document
                    // clearNotifications(); // OLD: Was local script.js notifications
                    if (typeof clearAllCurrentUserNotifications === 'function') {
                        clearAllCurrentUserNotifications();
                        console.log("[Main Interface] Called global clearAllCurrentUserNotifications.");
                    } else {
                        console.error("[Main Interface] clearAllCurrentUserNotifications is not defined.");
                    }
                    });
                }
            }
            
        // Global click listener to close notification panel if open and click is outside
                document.addEventListener('click', function(e) {
            if (panel && !panel.classList.contains('hidden')) { // If panel is open
                // Check if the click was outside the panel AND outside the bell
                    if (!panel.contains(e.target) && !bell.contains(e.target)) {
                        panel.classList.add('hidden');
                }
            }
        });
        
        // Add welcome notification using the local showNotification
            // showNotification('Welcome!', 'Welcome to FocusOS. Start your productive journey!', 'info'); // This is a local toast, can be kept or removed

        // Image Upload Logic for Daphinix in main interface
        const $uploadImageBtn = $("#upload-image-btn");
        const $imageUpload = $("#image-upload"); // The hidden file input
        const $imagePreviewContainer = $("#image-preview-container");
        const $imagePreview = $("#image-preview");
        const $removeImageBtn = $("#remove-image-btn");

        if ($uploadImageBtn.length && $imageUpload.length) {
            $uploadImageBtn.click(function() {
                $imageUpload.click(); // Trigger click on the hidden file input
            });
        }

        if ($imageUpload.length) {
            $imageUpload.change(function(e) {
                const file = e.target.files[0];
                if (file && $imagePreview.length && $imagePreviewContainer.length) {
                    const reader = new FileReader();
                    reader.onload = (event) => {
                        $imagePreview.attr("src", event.target.result);
                        $imagePreviewContainer.css("display", "flex");
                    };
                    reader.readAsDataURL(file);
                }
            });
        }

        if ($removeImageBtn.length) {
            $removeImageBtn.click(function() {
                $imagePreview.attr("src", "");
                $imagePreviewContainer.hide();
                $imageUpload.val(''); // Clear the file input
            });
        }

        // --- Inspire Me Feature ---
        const quotes = [
            "The best way to predict the future is to create it.",
            "Your limitation—it's only your imagination.",
            "Push yourself, because no one else is going to do it for you.",
            "Great things never come from comfort zones.",
            "Dream it. Wish it. Do it.",
            "Success doesn't just find you. You have to go out and get it.",
            "The harder you work for something, the greater you'll feel when you achieve it.",
            "Dream bigger. Do bigger.",
            "Don't stop when you're tired. Stop when you're done.",
            "Wake up with determination. Go to bed with satisfaction."
        ];

        // You'll need to replace these with actual image URLs or paths to your meme images
        // For local paths, they should be relative to the static folder, e.g., '/static/assets/memes/meme1.jpg'
        /* Predefined arrays are now removed
        const memes = [
            "/static/assets/images/memes/placeholder_meme_1.png", // Replace with actual meme paths/URLs
            "/static/assets/images/memes/placeholder_meme_2.png",
            "/static/assets/images/memes/placeholder_meme_3.png",
            "/static/assets/images/memes/placeholder_meme_4.png",
            "/static/assets/images/memes/placeholder_meme_5.png"
        ];
        */

        async function fetchAndDisplayInspireContent() {
            const quoteDisplay = $('#quote-display');
            const memeDisplay = $('#meme-display');
            const factDisplay = $('#fact-display'); // New element
            const promptDisplay = $('#thought-prompt-display'); // New element
            const refreshButton = $('#refresh-inspire-content');
            const memeCategorySelect = $('#meme-category-select');

            // Fade out old content for smoother transition
            $('#quote-container, #meme-container, #fact-container, #prompt-container').animate({opacity: 0.3}, 300);

            const originalButtonText = refreshButton.html(); 
            refreshButton.prop('disabled', true).html('<i class="fas fa-spinner fa-spin mr-2"></i>Loading...');

            const selectedMemeCategory = memeCategorySelect.val() || 'general';

            try {
                const response = await fetch(`/api/inspire?meme_category=${selectedMemeCategory}`);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const data = await response.json();

                if (quoteDisplay.length) {
                    quoteDisplay.html(`"${data.quote}" <br><em class="text-sm text-gray-400 block text-right mt-2">- ${data.author || 'Unknown'}</em>`);
                }
                if (promptDisplay.length) {
                    promptDisplay.text(data.prompt || "What are you grateful for today?");
                }
                if (factDisplay.length) {
                    factDisplay.text(data.fact || "Interesting facts are everywhere!");
                }

                if (memeDisplay.length) {
                    memeDisplay.attr('src', data.meme_url);
                    memeDisplay.off('error'); 
                    memeDisplay.on('error', function() {
                        $(this).attr('src', '/static/assets/images/placeholder_meme.png'); 
                        showUIMessage("Meme Error", "Could not load the meme image. Displaying a placeholder.", "warning");
                    });
                }
                // Update dropdown to reflect the category actually used by backend (if different due to fallback)
                if (data.selected_meme_category) {
                    memeCategorySelect.val(data.selected_meme_category);
                }

                // Fade in new content
                $('#quote-container, #meme-container, #fact-container, #prompt-container').stop(true, true).animate({opacity: 1}, 500);

            } catch (error) {
                console.error("Error fetching inspire content:", error);
                if (quoteDisplay.length) quoteDisplay.text("Could not load inspiration. Please try again!");
                if (promptDisplay.length) promptDisplay.text("Take a moment to breathe deeply.");
                if (factDisplay.length) factDisplay.text("Did you know that smiling is contagious?");
                if (memeDisplay.length) memeDisplay.attr('src', '/static/assets/images/placeholder_meme.png');
                showUIMessage("API Error", "Could not fetch new inspiration. Please check your connection or try again later.", "error", false);
                // Still fade in the containers even if content is error message
                $('#quote-container, #meme-container, #fact-container, #prompt-container').stop(true, true).animate({opacity: 1}, 300);
            } finally {
                refreshButton.prop('disabled', false).html(originalButtonText); 
            }
        }

        // Event listener for the refresh button in Inspire Me panel
        $(document).on('click', '#refresh-inspire-content', function() {
            playSound("sound-click");
            fetchAndDisplayInspireContent();
        });

        // Event listener for meme category change
        $(document).on('change', '#meme-category-select', function() {
            playSound("sound-click");
            fetchAndDisplayInspireContent(); // Refresh content when category changes
        });

        // Event listener for when the Inspire tab itself is clicked (to load content if it's the first time)
        // The main tab click handler already exists, we just need to ensure content is loaded if panel becomes active.
        // Consider adding a check within the main tab click handler if this specific panel is targeted,
        // or simply rely on the initial load and the refresh button.
        // For simplicity, the initial load is done in $(document).ready(), and refresh button handles subsequent ones.
        // If the inspire panel might be hidden initially and then shown, and needs fresh content upon first view (not just refresh):
        $('button[data-target="inspire-panel"]').on('click', function() {
            // Check if the panel is becoming active and if it needs an initial fetch beyond document.ready
            // This might be redundant if fetchAndDisplayInspireContent() is light enough or if initial load is sufficient.
            // For now, main load is on document.ready and refresh button.
            // If content should ALWAYS refresh when tab is clicked:
            // fetchAndDisplayInspireContent(); 
        });

        $(document).one('click keydown touchstart', function() { // Combined unlock events
            if (!audioUnlocked) { // Ensure this block runs only once as unlockAudio itself is {once: true}
                // The unlockAudio function already handles playing a dummy sound to unlock context.
                // Now, if rain is the selected default, try to play it specifically after this first interaction.
                const selectedSound = $("#ambient-sound-select").val();
                if (selectedSound === "rain") {
                    const rainAudio = $("#ambient-rain")[0];
                    if (rainAudio && rainAudio.paused) { // Check if it's not already playing
                        rainAudio.play().catch(e => console.warn("Error playing default rain sound after interaction:", e));
                    }
                }
            }
        });

        // Event listener for clicking on a background item in the modal grid
        $(document).on('click', '#bg-modal-grid-container .background-item-card', function() {
            const selectedId = $(this).data('id');
            applyPageBackground(selectedId);
            currentSelectedBackgroundId = selectedId; // Update the main variable here
            
            // Update selected state visual on cards within the modal grid
            $('#bg-modal-grid-container .background-item-card').removeClass('selected');
            $(this).addClass('selected');
            
            const selectedOption = backgroundOptions.find(opt => opt.id === selectedId);
            if (selectedOption) {
                $currentBgNameDisplay.text(selectedOption.name);
            }
            playSound("sound-click");
            showUIMessage("Environment", `Background changed to ${selectedOption.name}.`, "info", true);
            // Optionally close modal after selection
            // $backgroundModal.css('display', 'none'); 
        });

        $('#leaderboard-modal-close-btn, #leaderboard-modal-overlay').on('click', function() {
            $('#leaderboard-modal').addClass('hidden');
        });

        // Event listeners for leaderboard type buttons
        $('#leaderboard-xp-btn').on('click', function() {
            fetchAndRenderLeaderboard('xp');
            $('#leaderboard-xp-btn').addClass('bg-indigo-500').removeClass('bg-gray-700');
            $('#leaderboard-streak-btn').removeClass('bg-indigo-500').addClass('bg-gray-700');
        });

        $('#leaderboard-streak-btn').on('click', function() {
            fetchAndRenderLeaderboard('streak');
            $('#leaderboard-streak-btn').addClass('bg-indigo-500').removeClass('bg-gray-700');
            $('#leaderboard-xp-btn').removeClass('bg-indigo-500').addClass('bg-gray-700');
        });

        async function loadLeaderboardData(type) {
            console.log(`[Leaderboard] Loading data for type: ${type}`);
            try {
                const response = await fetch(`/api/leaderboard/${type}`);
                if (!response.ok) {
                    throw new Error(`Failed to fetch leaderboard: ${response.statusText}`);
                }
                const data = await response.json();
                console.log(`[Leaderboard] Received data for ${type}:`, data);
                return data;
            } catch (error) {
                console.error(`[Leaderboard] Error loading leaderboard data for ${type}:`, error);
                showUIMessage("Leaderboard Error", "Could not load leaderboard data.", "error");
                return []; // Return empty array on error
            }
        }
    
        async function fetchAndRenderLeaderboard(type) {
            const $tbodyAll        = $("#leaderboard-table-body, #stats-panel #leaderboard-table-body, #leaderboard-panel #leaderboard-table-body");
            const $loadingAll      = $("#leaderboard-loading, #stats-panel #leaderboard-loading, #leaderboard-panel #leaderboard-loading");
            const $errorAll        = $("#leaderboard-error, #stats-panel #leaderboard-error, #leaderboard-panel #leaderboard-error");
            const $noDataAll       = $("#no-leaderboard-data, #stats-panel #no-leaderboard-data, #leaderboard-panel #no-leaderboard-data");
            let currentFirebaseUser = null;
            try {
                 currentFirebaseUser = await window.firebaseAuthReady;
            } catch (e) {
                console.warn("Could not get current Firebase user for leaderboard context:", e);
            }
            const currentUsername = currentUserProgress?.username || (currentFirebaseUser ? currentFirebaseUser.displayName || currentFirebaseUser.email : null) || 'You'; // Fallback for display

            $tbodyAll.empty();
            $loadingAll.removeClass("hidden");
            $errorAll.addClass("hidden");
            $noDataAll.addClass("hidden");

            try {
                const leaderboardData = await loadLeaderboardData(type);
                if (leaderboardData && leaderboardData.length > 0) {
                    let currentUserData = null;
                    let currentUserRank = -1;

                    leaderboardData.forEach((entry, index) => {
                        if (entry.username === currentUserProgress.username) { // Assuming currentUserProgress.username is the unique ID
                            currentUserData = entry;
                            currentUserRank = entry.rank;
                        }
                    });

                    const displayEntries = [];
                    const addedUsernames = new Set();

                    // 1. Add Top 3
                    for (let i = 0; i < Math.min(3, leaderboardData.length); i++) {
                        displayEntries.push(leaderboardData[i]);
                        addedUsernames.add(leaderboardData[i].username);
                    }

                    // 2. Add Current User and Neighbors (if not already in top 3)
                    if (currentUserData && currentUserRank > 3) {
                        const userIndexInFetchedData = leaderboardData.findIndex(u => u.username === currentUserData.username);
                        if (userIndexInFetchedData !== -1) {
                            // Add a separator if there's a gap between top 3 and user's section
                            if (displayEntries.length > 0 && leaderboardData[userIndexInFetchedData-1] && 
                                !addedUsernames.has(leaderboardData[userIndexInFetchedData-1].username) && 
                                userIndexInFetchedData > displayEntries.length) { // Check if the preceding element is not the last of top 3
                                displayEntries.push({isSeparator: true});
                            }

                            // User -1 (if exists and not already added)
                            if (userIndexInFetchedData > 0 && !addedUsernames.has(leaderboardData[userIndexInFetchedData - 1].username)) {
                                displayEntries.push(leaderboardData[userIndexInFetchedData - 1]);
                                addedUsernames.add(leaderboardData[userIndexInFetchedData - 1].username);
                            }
                            // Current User (if not already added - should not happen if rank > 3)
                            if (!addedUsernames.has(currentUserData.username)){
                                displayEntries.push(currentUserData);
                                addedUsernames.add(currentUserData.username);
                            }
                            // User +1 (if exists and not already added)
                            if (userIndexInFetchedData < leaderboardData.length - 1 && !addedUsernames.has(leaderboardData[userIndexInFetchedData + 1].username)) {
                                displayEntries.push(leaderboardData[userIndexInFetchedData + 1]);
                                // addedUsernames.add(leaderboardData[userIndexInFetchedData + 1].username); // No need to add to set if it's the last one added in this block
                            }
                        }
                    } else if (currentUserData && currentUserRank <=3) {
                        // User is in top 3, already added. Do nothing special here.
                    } else if (!currentUserData && leaderboardData.length > 3) {
                         // User not in top 20, add a separator after top 3 if there are more entries.
                         displayEntries.push({isSeparator: true, customText: "Your rank is not in the top 20 for this board."})                    
                    }

                    displayEntries.forEach(entry => {
                        if (entry.isSeparator) {
                            const separatorText = entry.customText || "...";
                            const separatorRow = `
                                <tr>
                                    <td colspan="5" class="py-2 px-3 text-center text-gray-500 text-xs italic">${separatorText}</td>
                                </tr>
                            `;
                            $tbodyAll.append(separatorRow);
                            return;
                        }

                        let rankDisplay = entry.rank;
                        if (entry.rank === 1) rankDisplay = '🥇';
                        else if (entry.rank === 2) rankDisplay = '🥈';
                        else if (entry.rank === 3) rankDisplay = '🥉';
                        
                        const isCurrentUserEntry = entry.username === currentUserProgress.username;

                        const row = `
                            <tr class="text-sm ${isCurrentUserEntry ? 'bg-purple-700 bg-opacity-30 font-semibold' : 'hover:bg-gray-700 bg-opacity-50'} transition-colors">
                                <td class="py-2 px-3 border-b border-gray-700 text-center">${rankDisplay}</td>
                                <td class="py-2 px-3 border-b border-gray-700">${entry.username} ${isCurrentUserEntry ? '(You)' : ''}</td>
                                <td class="py-2 px-3 border-b border-gray-700 text-center">${entry.level}</td>
                                <td class="py-2 px-3 border-b border-gray-700 text-right">${entry.xp}</td>
                                <td class="py-2 px-3 border-b border-gray-700 text-center">${entry.streak}</td>
                            </tr>
                        `;
                        $tbodyAll.append(row);
                    });
                } else {
                    $noDataAll.removeClass("hidden");
                }
            } catch (err) {
                console.error("Error fetching leaderboard:", err);
                $errorAll.text("Error: " + err.message).removeClass("hidden");
            } finally {
                $loadingAll.addClass("hidden");
            }
        }
    }
});
