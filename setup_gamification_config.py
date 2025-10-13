import firebase_admin
from firebase_admin import credentials, firestore
from firebase_config import initialize_firebase # Assuming your service account key is handled here

# --- Define your Gamification Configuration Data ---
# You can and should customize xpValues, leveling, and especially quest definitions
# based on your application's needs.
# The badges section is based on our detailed discussion.

GAMIFICATION_CONFIG_DATA = {
    "xpValues": {
        "pomodoroMinute": 1,       # XP per minute of focused Pomodoro session
        "taskCompletion": 10,      # XP for completing a generic task (if applicable)
        "dailyLogin": 5,           # XP for daily login/first action (needs specific trigger logic)
        "questCompletionBase": 25  # Base XP for completing a quest, can be overridden by quest def
    },
    "leveling": {
        "baseXpForLevelUp": 100,   # XP needed to go from Level 1 to 2 (e.g., L * baseXp)
        "xpIncreasePerLevel": 50  # Additional XP needed per level (e.g. L * baseXp + (L-1)*xpIncrease)
                                    # Or simply (currentLevel * baseXpForLevelUp) as in script.js
    },
    "quests": { # Placeholder - define your actual quest templates here
        "daily": [
            {
                "templateId": "daily_pomodoro_short",
                "title": "Quick Focus",
                "descriptionTemplate": "Complete {N} Pomodoro session(s) today.",
                "goalType": "pomodoro_session_completed",
                "targetMin": 1,
                "targetMax": 2,
                "rewardXp": 30,
                "icon": "fa-stopwatch"
            },
            {
                "templateId": "daily_study_time_short",
                "title": "Study Sprint",
                "descriptionTemplate": "Study for {N} minutes today.",
                "goalType": "study_time_added",
                "targetMin": 30,
                "targetMax": 60,
                "rewardXp": 40,
                "icon": "fa-book-open"
            }
        ],
        "weekly": [
            {
                "templateId": "weekly_pomodoro_long",
                "title": "Marathon Focus",
                "descriptionTemplate": "Complete {N} Pomodoro sessions this week.",
                "goalType": "pomodoro_session_completed",
                "targetMin": 10,
                "targetMax": 15,
                "rewardXp": 150,
                "icon": "fa-dumbbell"
            },
            {
                "templateId": "weekly_study_time_long",
                "title": "Deep Dive Study",
                "descriptionTemplate": "Study for {N} minutes this week.",
                "goalType": "study_time_added",
                "targetMin": 300,
                "targetMax": 500,
                "rewardXp": 200,
                "icon": "fa-brain"
            }
        ]
    },
    "badges": {
        "first_steps": {
            "name": "First Steps",
            "description": "Complete your first Pomodoro session.",
            "icon": "fa-shoe-prints",
            "color": "#A0522D",
            "textColor": "#FFFFFF",
            "type": "session_count", # or "pomodoro_count" if more specific
            "targetCount": 1,
            "tier": 0 # Optional: base tier
        },
        # Pomodoro Tiered Badges
        "pomodoro_pro_bronze": {
            "name": "Pomodoro Pro (Bronze)",
            "description": "Complete 10 Pomodoro sessions.",
            "icon": "fa-stopwatch",
            "color": "#CD7F32", # Bronze
            "textColor": "white",
            "type": "pomodoro_count",
            "targetCount": 10,
            "tier": 1
        },
        "pomodoro_pro_silver": {
            "name": "Pomodoro Pro (Silver)",
            "description": "Complete 50 Pomodoro sessions.",
            "icon": "fa-stopwatch",
            "color": "#C0C0C0", # Silver
            "textColor": "#333333",
            "type": "pomodoro_count",
            "targetCount": 50,
            "tier": 2
        },
        "pomodoro_pro_gold": {
            "name": "Pomodoro Pro (Gold)",
            "description": "Complete 200 Pomodoro sessions.",
            "icon": "fa-stopwatch",
            "color": "#FFD700", # Gold
            "textColor": "#333333",
            "type": "pomodoro_count",
            "targetCount": 200,
            "tier": 3
        },
        "pomodoro_pro_platinum": {
            "name": "Pomodoro Pro (Platinum)",
            "description": "Complete 500 Pomodoro sessions.",
            "icon": "fa-stopwatch",
            "color": "#E5E4E2", # Platinum
            "textColor": "#333333",
            "type": "pomodoro_count",
            "targetCount": 500,
            "tier": 4
        },
        # Study Time Tiered Badges
        "study_time_bronze": {
            "name": "Time Scholar (Bronze)",
            "description": "Study for 300 minutes total.",
            "icon": "fa-book-reader",
            "color": "#CD7F32",
            "textColor": "white",
            "type": "study_time",
            "targetMinutes": 300,
            "tier": 1
        },
        "study_time_silver": {
            "name": "Time Scholar (Silver)",
            "description": "Study for 1000 minutes total.",
            "icon": "fa-book-reader",
            "color": "#C0C0C0",
            "textColor": "#333333",
            "type": "study_time",
            "targetMinutes": 1000,
            "tier": 2
        },
        "study_time_gold": {
            "name": "Time Scholar (Gold)",
            "description": "Study for 5000 minutes. Mad respect.",
            "icon": "fa-book-reader",
            "color": "#FFD700",
            "textColor": "#333333",
            "type": "study_time",
            "targetMinutes": 5000,
            "tier": 3
        },
        "study_time_platinum": {
            "name": "Time Scholar (Platinum)",
            "description": "Study for 10,000+ minutes. You're cracked.",
            "icon": "fa-book-reader",
            "color": "#E5E4E2",
            "textColor": "#333333",
            "type": "study_time",
            "targetMinutes": 10000,
            "tier": 4
        },
        # Streak Tiered Badges
        "streak_master_bronze": {
            "name": "Streak Starter (Bronze)",
            "description": "Achieve a 3-day study streak.",
            "icon": "fa-fire-alt",
            "color": "#CD7F32",
            "textColor": "white",
            "type": "streak",
            "targetStreak": 3,
            "tier": 1
        },
        "streak_master_silver": {
            "name": "On Fire (Silver)",
            "description": "Achieve a 7-day study streak.",
            "icon": "fa-fire-alt",
            "color": "#C0C0C0",
            "textColor": "#333333",
            "type": "streak",
            "targetStreak": 7,
            "tier": 2
        },
        "streak_master_gold": {
            "name": "Never Miss (Gold)",
            "description": "Achieve a 14-day study streak.",
            "icon": "fa-fire-alt",
            "color": "#FFD700",
            "textColor": "#333333",
            "type": "streak",
            "targetStreak": 14,
            "tier": 3
        },
        "streak_master_platinum": {
            "name": "The Unbreakable (Platinum)",
            "description": "Achieve a 30-day study streak.",
            "icon": "fa-fire-alt",
            "color": "#E5E4E2",
            "textColor": "#333333",
            "type": "streak",
            "targetStreak": 30,
            "tier": 4
        },
        # Time-of-Day Badges
        "focused_morning": {
            "name": "Focused Morning",
            "description": "Completed a study session between 6 AM and 12 PM UTC.",
            "icon": "fa-sun",
            "color": "#FFD700", # Bright yellow
            "textColor": "#333333",
            "type": "time_of_day",
            "targetHoursUTC": [6, 12] # 6:00 to 11:59 UTC
        },
        "afternoon_achiever": {
            "name": "Afternoon Achiever",
            "description": "Studied between 12 PM and 6 PM UTC.",
            "icon": "fa-cloud-sun", # Icon suggesting afternoon
            "color": "#FF8C00", # Dark Orange
            "textColor": "white",
            "type": "time_of_day",
            "targetHoursUTC": [12, 18] # 12:00 to 17:59 UTC
        },
        "evening_scholar": {
            "name": "Evening Scholar",
            "description": "Studied between 6 PM and 10 PM UTC.",
            "icon": "fa-moon", # Simple moon for evening
            "color": "#6A5ACD", # Slate Blue / Lavender
            "textColor": "white",
            "type": "time_of_day",
            "targetHoursUTC": [18, 22] # 18:00 to 21:59 UTC
        },
        "midnight_oil_burner": {
            "name": "Midnight Oil Burner",
            "description": "Active study session between 10 PM and 3 AM UTC.",
            "icon": "fa-ghost", # Playful icon for late night
            "color": "#4B0082", # Indigo
            "textColor": "white",
            "type": "time_of_day",
            "targetHoursUTC": [22, 3] # 22:00 to 2:59 UTC (next day)
        }
        # Add any other generic/single-instance badges here if needed
    }
}

def setup_gamification_config():
    """
    Initializes or updates the gamification_config/settings document in Firestore.
    """
    try:
        db = initialize_firebase()
        if not db:
            print("Failed to initialize Firebase. Exiting.")
            return

        config_ref = db.collection('gamification_config').document('settings')
        
        print(f"Setting gamification configuration for document: {config_ref.path}")
        config_ref.set(GAMIFICATION_CONFIG_DATA)
        print("Successfully set/updated gamification configuration in Firestore!")
        
        # Optionally, verify by fetching the document
        # doc = config_ref.get()
        # if doc.exists:
        #     print(f"Verified document content: {doc.to_dict()}")
        # else:
        #     print("Error: Document not found after setting.")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == '__main__':
    print("Attempting to set up gamification configuration in Firestore...")
    print("IMPORTANT: This script will OVERWRITE the existing 'gamification_config/settings' document.")
    # confirm = input("Are you sure you want to proceed? (yes/no): ")
    # if confirm.lower() == 'yes':
    #     setup_gamification_config()
    # else:
    #     print("Operation cancelled by user.")
    # For automated execution, you might remove the confirmation.
    # Be cautious if running this multiple times without intending to overwrite.
    setup_gamification_config() 