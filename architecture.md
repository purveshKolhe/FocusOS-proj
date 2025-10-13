# FocusOS Architecture Description

FocusOS is a web application designed to enhance productivity and focus through various features like a Pomodoro timer, AI chatbot, gamification, and collaborative study rooms with real-time video/audio. The application is built using Flask for the backend, Firebase for authentication and data storage, and integrates with several external APIs for enhanced functionality.

## File and Folder Structure

The project is organized into a clear and modular structure:

- `/` (Parent Directory)
    - `.env`: Environment variables for configuration (e.g., API keys, secret key).
    - `.gitignore`: Specifies intentionally untracked files to ignore.
    - `app.py`: The main Flask application file, containing all routes, core logic, and API integrations.
    - `architecture.md`: This document, describing the application's architecture.
    - `chat`: (Assumed to be a file, not a directory, based on previous listing) Potentially a placeholder or an old chat-related file.
    - `firebase_config.py`: Configuration and initialization for Firebase services, and data access functions for Firestore.
    - `gamification_logic.py`: Contains logic related to gamification features like XP, levels, streaks, quests, and badges.
    - `README.md`: Project README file.
    - `requirements.txt`: Lists Python dependencies for the project.
    - `serviceAccountKey.json`: Firebase service account key for server-side authentication.
    - `setup_gamification_config.py`: Script for setting up initial gamification configurations in Firestore.
    - `static/`:
        - `assets/`:
            - `images/`: Stores static image assets.
            - `sounds/`: Stores audio files for notifications or background sounds.
            - `videos/`: Stores video assets.
        - `css/`:
            - `styles.css`: Contains the main CSS stylesheets for the application's visual design.
        - `js/`:
            - `script.js`: Main JavaScript file for client-side logic and interactions.
            - `libraries/`: (Assumed) May contain third-party JavaScript libraries.
        - `lib/`: (New) May contain additional client-side libraries or assets.
    - `templates/`:
        - `auth/`: (New) Contains authentication-related HTML templates (e.g., `login.html`, `register.html`).
        - `admin_content.html`: (New) Template for the admin content management page.
        - `base.html`: Base template for common page structure.
        - `create_room.html`: Page for creating new study rooms.
        - `index.html`: The main landing page or dashboard.
        - `join_room.html`: Page for joining existing study rooms.
        - `study_room.html`: Template for collaborative study rooms.
        - Other HTML templates for various application views.
    - `__pycache__/`: Python bytecode cache.
    - `focusos-main/`: (Potentially a sub-project or old structure, contains `static/`)

## What Each Part Does

### `app.py`
This is the heart of the application, handling:
- **Flask Application Setup**: Initializes the Flask app, secret key (loaded from `.env`), and integrates with SocketIO. Uses `python-dotenv` for environment variable management and `pathlib.Path` for robust path handling.
- **Authentication & User Management**:
    - `login_required` decorator for protecting routes.
    - Routes for user login (`/login`), registration (`/register`), and logout (`/logout`).
    - Integrates with **Firebase Authentication** for user sign-up and sign-in, creating and managing user accounts.
    - Uses `werkzeug.security` for secure password hashing.
    - Manages user data (XP, streaks, quests, badges, session history, leaderboard data) in Firestore.
- **AI Chatbot Integration (Daphinix)**:
    - Configures and interacts with **Google Generative AI (Gemini 2.5 Flash Lite)** models (`gemini-2.5-flash-lite-preview-06-17`).
    - `SYSTEM_PROMPT` defines the AI chatbot's persona ("Daphinix"), detailed formatting rules (including LaTeX for mathematical expressions), and personality traits.
    - `custom_chat` handles text-based chat interactions, including detection and specialized formatting for math questions.
    - `process_image_request` handles multimodal chat interactions (image + text).
    - `/api/chat` and `/api/chat_with_image` endpoints for client-side chat requests.
- **Study Room Functionality**:
    - `/create-room` and `/join-room` routes for managing study sessions.
    - `study_room` route renders the collaborative room interface.
    - Uses SocketIO for real-time communication within rooms:
        - `join_room`, `send_room_message`, `leave_room`, `disconnect` events.
        - Manages participants, chat messages, and room state in Firestore.
        - Implements a shared Pomodoro timer for rooms, with `start_room_timer` and `stop_room_timer` functions, and state persisted in Firestore.
        - `/api/room_chat_history` and `/api/room_participants` endpoints.
    - **Real-time Video/Audio**: Integrates with **Agora.io** for video/audio communication, using `agora_token_builder` to generate RTC tokens.
- **Gamification & Leaderboard**:
    - Updates user progress (XP, streaks, levels, badges) based on session completion.
    - **Quests**: Implements daily and weekly quests with dynamic assignment, progress tracking, and XP rewards.
    - **Badges**: Awards badges based on various criteria (e.g., session count, study time, streak, time of day).
    - `/api/leaderboard/<type>` endpoint to fetch leaderboard data (XP or streak).
    - Interacts with `gamification_logic.py` for all gamification calculations and updates.
- **Inspiration Content**:
    - `/api/inspire` endpoint fetches random quotes (ZenQuotes), memes (Meme API), and facts (UselessFacts API).
- **Todo List Management**:
    - `/api/todo_list` endpoints for getting and saving user-specific todo items, including status and completion tracking.
- **Admin Content Management**:
    - `/admin/content` route allows administrators to add new backgrounds, background music (BGMs), badges, and quests directly to the Firestore database.
- **Background Tasks**:
    - `cleanup_orphaned_rooms` thread periodically checks and deletes empty study rooms from Firestore.

### `firebase_config.py`
- Contains the necessary Firebase project configuration and initialization logic.
- Provides functions (`initialize_firebase`, `get_user_data`, `save_user_data`, `get_chat_history`, `save_chat_history`, `get_todo_list`, `save_todo_list`) to interact with Firestore for various data operations.

### `gamification_logic.py`
- Contains the core logic for the gamification system.
- Functions include:
    - `calculate_xp_for_session`: Determines XP earned for a study session.
    - `check_for_levelup`: Manages user leveling based on XP.
    - `update_study_streak`: Tracks and updates user study streaks.
    - `check_and_award_badges`: Awards badges based on predefined criteria and user progress.
    - `assign_new_quests`: Assigns daily and weekly quests to users.
    - `update_quest_progress`: Tracks and updates progress for active quests.
    - `update_leaderboard_data`: Denormalizes user progress data for efficient leaderboard queries.
- Fetches gamification settings (XP values, leveling, badges, quests) from a dedicated `gamification_config/settings` document in Firestore.

### `static/`
- **`assets/`**: Stores media files (images, sounds, videos) used throughout the application.
- **`css/styles.css`**: Defines the visual styling, layout, and responsiveness of the web pages.
- **`js/script.js`**: Handles client-side interactivity, AJAX requests to Flask backend, SocketIO communication, and dynamic updates to the UI.
- **`lib/`**: Contains additional client-side libraries or assets.

### `templates/`
- Contains Jinja2 templates for rendering dynamic HTML pages. Each `.html` file corresponds to a specific view or section of the application.
- `auth/` subdirectory for authentication-related templates.
- `admin_content.html` for the admin interface.

## State Management and Service Connections

### State Management
- **Client-Side State**: Managed primarily by JavaScript (`script.js`) for UI interactions, form data, and real-time updates received via WebSockets.
- **Server-Side State**:
    - **Firebase Firestore**: The primary database for persistent data storage.
        - **User Data**: Stores user profiles, progress (XP, level, streak), quests (active and completed), badges, and session history.
        - **Study Room Data**: Stores room details (ID, creator, participants), chat messages, and shared timer state.
        - **Todo Lists**: Stores user-specific todo items.
        - **Chat History**: Stores AI chatbot conversation logs.
        - **Gamification Configuration**: Stores global settings for XP, leveling, badges, and quests.
        - **Admin Content**: Stores backgrounds, BGMs, and other content managed by the admin interface.
    - **Flask Session**: Used for managing user login sessions (`session['user_id']`, `session['firebase_custom_token']`).
    - **In-memory Dictionaries (Server-side)**:
        - `active_sessions`: Maps SocketIO SIDs to user and room information for active WebSocket connections.
        - `room_timers`: Stores `threading.Thread` and `threading.Event` objects for managing individual room timers, allowing them to run independently and be stopped.

### Service Connections

- **Flask (Python Backend)**:
    - **Firebase**: Connects to Firebase Authentication for user identity management and Firestore for NoSQL database operations (storing user data, room data, chat history, todos, gamification config, admin content).
    - **SocketIO**: Integrates with Flask-SocketIO to enable real-time, bidirectional communication between the server and clients for features like live chat in study rooms and synchronized timers.
    - **Google Generative AI API**: Connects to Google's **Gemini 2.5 Flash Lite** models for the AI chatbot functionality (text and multimodal).
    - **Agora.io**: Used for real-time video/audio communication in study rooms, leveraging `agora_token_builder` for token generation.
    - **External APIs (HTTP Requests)**:
        - `ZenQuotes.io`: Fetches random inspirational quotes.
        - `Meme-API.com`: Retrieves random memes from specified subreddits.
        - `UselessFacts.jsph.pl`: Provides random fun facts.
    - **`python-dotenv`**: Loads environment variables from `.env` file.
    - **`werkzeug.security`**: Used for password hashing.

- **Client-Side (HTML, CSS, JavaScript)**:
    - **Flask Backend**: Communicates with Flask routes via AJAX requests (e.g., fetching user data, saving todos, getting inspiration content).
    - **SocketIO**: Establishes WebSocket connections to the Flask-SocketIO server for real-time updates (chat messages, timer synchronization, participant changes).
    - **Firebase Client SDK**: (Implied) May be used directly on the client for certain Firebase functionalities like real-time listeners or specific authentication flows.

This architecture provides a robust and scalable foundation for FocusOS, leveraging cloud services, real-time communication, and advanced AI capabilities to deliver a dynamic and engaging user experience.