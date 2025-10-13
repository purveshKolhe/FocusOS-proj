from datetime import datetime, timedelta, timezone
import random

# --- Firestore Document References ---
def get_gamification_config_ref(db):
    return db.collection('gamification_config').document('settings')

def get_user_ref(db, user_id):
    return db.collection('users').document(user_id)

# --- XP & Leveling ---
def calculate_xp_for_session(duration_minutes, gamification_settings):
    """Calculates XP earned for a study session."""
    xp_per_minute = gamification_settings.get('xpValues', {}).get('perPomodoroWorkMinute', 1) # Default to 1 if not set
    return duration_minutes * xp_per_minute

def check_for_levelup(user_progress, gamification_settings):
    """Checks if user leveled up and updates XP and level."""
    leveled_up = False
    xp_for_next_level_setting = gamification_settings.get('leveling', {}).get('baseXpForLevelUp', 100)
    
    xp_needed_for_next = user_progress.get('level', 1) * xp_for_next_level_setting
    
    while user_progress.get('xp', 0) >= xp_needed_for_next:
        user_progress['level'] = user_progress.get('level', 1) + 1
        user_progress['xp'] -= xp_needed_for_next
        leveled_up = True
        # Recalculate for potential multiple level-ups
        xp_needed_for_next = user_progress.get('level', 1) * xp_for_next_level_setting
        if xp_needed_for_next <= 0: # Safety break for bad config
            break
            
    return leveled_up

# --- Streak Logic ---
def update_study_streak(user_progress):
    """Updates the user's study streak based on the current date and last study day."""
    today_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    last_study_day_str = user_progress.get('lastStudyDay')
    current_streak = user_progress.get('streak', 0)

    if last_study_day_str == today_str:
        # Already studied today, streak doesn't change for this specific session,
        # but lastStudyDay is confirmed as today.
        pass
    elif last_study_day_str:
        try:
            last_study_date = datetime.strptime(last_study_day_str, '%Y-%m-%d').date()
            today_date = datetime.strptime(today_str, '%Y-%m-%d').date()
            delta = today_date - last_study_date
            
            if delta.days == 1:
                current_streak += 1
            elif delta.days > 1:
                current_streak = 1 # Reset streak if missed more than a day
            # If delta.days <= 0 (e.g. system clock moved back), keep current streak or set to 1.
            # For simplicity, if it's a new day, it's at least 1.
            else: # Should ideally not happen if today_str > last_study_day_str
                 current_streak = 1

        except ValueError:
            # Invalid last_study_day_str format
            current_streak = 1
    else:
        # No last study day recorded, this is the first study day or first since reset
        current_streak = 1
        
    user_progress['streak'] = current_streak
    user_progress['lastStudyDay'] = today_str
    return current_streak # Return the new streak

# --- Badge Logic ---
def check_and_award_badges(user_progress, gamification_settings, event_info=None):
    """
    Checks user progress against badge criteria and awards new badges.
    Handles tiered badges by their unique IDs.

    Args:
        user_progress (dict): The user's current progress data.
        gamification_settings (dict): The global gamification settings.
        event_info (dict, optional): Information about the event triggering the check,
                                     e.g., {'type': 'session_complete', 'duration': 25, 'time_completed_hour_utc': 14}.

    Returns:
        list: A list of badge_ids for newly awarded badges.
    """
    if not user_progress or not gamification_settings:
        return []

    newly_awarded_badges = []
    current_badges = set(user_progress.get("badges", [])) # Use a set for efficient lookup
    all_badge_definitions = gamification_settings.get("badges", {})

    # Default user progress values if not present
    sessions_completed = user_progress.get("sessions", 0) # Assuming 'sessions' tracks completed Pomodoro/work sessions
    total_study_time_minutes = user_progress.get("total_time", 0)
    current_streak = user_progress.get("streak", 0)

    for badge_id, badge_def in all_badge_definitions.items():
        if badge_id in current_badges:
            continue  # User already has this badge

        awarded = False
        badge_type = badge_def.get("type")

        try:
            if badge_type == "session_count":
                if sessions_completed >= badge_def.get("targetCount", float('inf')):
                    awarded = True
            elif badge_type == "pomodoro_count": # Assuming 'sessions' field in user_progress counts Pomodoros
                if sessions_completed >= badge_def.get("targetCount", float('inf')):
                    awarded = True
            elif badge_type == "study_time":
                if total_study_time_minutes >= badge_def.get("targetMinutes", float('inf')):
                    awarded = True
            elif badge_type == "streak":
                if current_streak >= badge_def.get("targetStreak", float('inf')):
                    awarded = True
            elif badge_type == "time_of_day":
                if event_info and event_info.get("type") == "session_complete":
                    hour_completed_utc = event_info.get("time_completed_hour_utc")
                    target_hours_utc = badge_def.get("targetHoursUTC")

                    if hour_completed_utc is not None and isinstance(target_hours_utc, list) and len(target_hours_utc) == 2:
                        start_hour, end_hour = target_hours_utc[0], target_hours_utc[1]
                        
                        # Validate hours are integers
                        if not (isinstance(start_hour, int) and isinstance(end_hour, int) and \
                                0 <= start_hour <= 23 and 0 <= end_hour <= 23):
                            print(f"Warning: Invalid targetHoursUTC for badge {badge_id}: {target_hours_utc}. Skipping.")
                            continue

                        if start_hour <= end_hour: # Normal period (e.g., 6 AM to 12 PM is [6, 12])
                            # End hour is typically exclusive for ranges, so session must be < end_hour
                            if start_hour <= hour_completed_utc < end_hour:
                                awarded = True
                        else: # Overnight period (e.g., 10 PM to 3 AM is [22, 3])
                            if hour_completed_utc >= start_hour or hour_completed_utc < end_hour:
                                awarded = True
            # Add more badge type checks here if new types are introduced

            if awarded:
                newly_awarded_badges.append(badge_id)
                current_badges.add(badge_id) # Add to set to prevent re-awarding in same call if multiple badges of same type exist

        except Exception as e:
            print(f"Error processing badge {badge_id} of type {badge_type}: {e}")
            # Continue to next badge, don't let one bad definition stop others

    if newly_awarded_badges:
        user_progress["badges"] = list(current_badges) # Update user_progress with the full list of badges

    return newly_awarded_badges

# --- Quest Logic ---
def get_next_day_or_week_start(frequency, current_dt_utc):
    """Calculates the start of the next day or week in UTC."""
    if frequency == "daily":
        next_start = (current_dt_utc + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    elif frequency == "weekly":
        # Next Monday 00:00 UTC
        days_until_monday = (7 - current_dt_utc.weekday()) % 7
        if days_until_monday == 0: # If today is Monday, then next week's Monday
            days_until_monday = 7
        next_start = (current_dt_utc + timedelta(days=days_until_monday)).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        next_start = current_dt_utc + timedelta(days=1) # Default to daily if unknown
    return next_start

def assign_new_quests(user_progress, gamification_settings):
    """Assigns new daily/weekly quests if they are due."""
    newly_assigned_quests_info = []
    if not gamification_settings or 'quests' not in gamification_settings:
        return newly_assigned_quests_info

    now_utc = datetime.now(timezone.utc)
    active_quests = user_progress.get('activeQuests', [])
    
    # Filter out expired quests
    active_quests = [q for q in active_quests if q.get('expiryDate') and datetime.fromisoformat(q['expiryDate']) > now_utc]

    quest_config = gamification_settings['quests']
    
    # Assign Daily Quests
    needs_daily_quest = not any(q.get('frequency') == 'daily' for q in active_quests)
    if needs_daily_quest and 'daily' in quest_config and quest_config['daily']:
        template = random.choice(quest_config['daily'])
        target_val = random.randint(template['targetMin'], template['targetMax'])
        
        quest_id = f"{template['templateId']}_{now_utc.strftime('%Y-%m-%d')}"
        description = template['descriptionTemplate'].replace("{N}", str(target_val))
        expiry = get_next_day_or_week_start("daily", now_utc)

        new_quest = {
            "questId": quest_id,
            "templateId": template['templateId'],
            "title": template['title'],
            "description": description,
            "goalType": template['goalType'],
            "currentProgress": 0,
            "targetProgress": target_val,
            "rewardXp": template['rewardXp'],
            "assignedDate": now_utc.isoformat(),
            "expiryDate": expiry.isoformat(),
            "frequency": "daily",
            "status": "active"
        }
        active_quests.append(new_quest)
        newly_assigned_quests_info.append(new_quest['title'])

    # Assign Weekly Quests
    needs_weekly_quest = not any(q.get('frequency') == 'weekly' for q in active_quests)
    if needs_weekly_quest and 'weekly' in quest_config and quest_config['weekly']:
        template = random.choice(quest_config['weekly'])
        target_val = random.randint(template['targetMin'], template['targetMax'])

        quest_id = f"{template['templateId']}_{now_utc.strftime('%Y-%U')}" # Year-WeekNumber
        description = template['descriptionTemplate'].replace("{N}", str(target_val))
        expiry = get_next_day_or_week_start("weekly", now_utc)
        
        new_quest = {
            "questId": quest_id,
            "templateId": template['templateId'],
            "title": template['title'],
            "description": description,
            "goalType": template['goalType'],
            "currentProgress": 0,
            "targetProgress": target_val,
            "rewardXp": template['rewardXp'],
            "assignedDate": now_utc.isoformat(),
            "expiryDate": expiry.isoformat(),
            "frequency": "weekly",
            "status": "active"
        }
        active_quests.append(new_quest)
        newly_assigned_quests_info.append(new_quest['title'])
        
    user_progress['activeQuests'] = active_quests
    return newly_assigned_quests_info


def update_quest_progress(user_progress, gamification_settings, event_info):
    """
    Updates progress for active quests based on an event.
    event_info: {'type': 'pomodoro_session_completed', 'value': 1}
                {'type': 'study_time_added', 'value': 25 (minutes)}
                {'type': 'task_completed', 'taskId': 'xyz'}
    Returns list of completed quest titles.
    """
    completed_quest_titles = []
    if 'activeQuests' not in user_progress or not user_progress['activeQuests']:
        return completed_quest_titles

    now_utc = datetime.now(timezone.utc)
    event_type = event_info.get('type')
    event_value = event_info.get('value', 1)

    new_active_quests = []
    completed_quests_store = user_progress.get('completedQuests', [])

    for quest in user_progress['activeQuests']:
        if quest.get('status') == 'completed': # Should not happen if filtered before
            new_active_quests.append(quest)
            continue
        
        if quest.get('expiryDate') and datetime.fromisoformat(quest['expiryDate']) <= now_utc:
            quest['status'] = 'expired' # Mark as expired, will be filtered out next time
            new_active_quests.append(quest) # Or just don't add it
            continue

        quest_updated = False
        if quest['goalType'] == 'pomodoro_sessions' and event_type == 'pomodoro_session_completed':
            quest['currentProgress'] = min(quest['currentProgress'] + event_value, quest['targetProgress'])
            quest_updated = True
        elif quest['goalType'] == 'study_time' and event_type == 'study_time_added': # expecting minutes
            quest['currentProgress'] = min(quest['currentProgress'] + event_value, quest['targetProgress'])
            quest_updated = True
        elif quest['goalType'] == 'study_time_hours' and event_type == 'study_time_added': # expecting minutes
             # Convert event_value (minutes) to hours for progress if goal is in hours
            quest['currentProgress'] = min(quest['currentProgress'] + (event_value / 60.0), quest['targetProgress'])
            # Ensure progress is stored reasonably (e.g., 2 decimal places for hours)
            quest['currentProgress'] = round(quest['currentProgress'], 2)
            quest_updated = True
        # TODO: Add 'task_completed' goalType if needed
        
        if quest_updated and quest['currentProgress'] >= quest['targetProgress']:
            quest['status'] = 'completed'
            reward = quest.get('rewardXp', 0)
            user_progress['xp'] = user_progress.get('xp', 0) + reward
            # Add to cumulative XP as well
            user_progress['totalXp'] = user_progress.get('totalXp', 0) + reward
            completed_quests_store.append(quest['questId'])
            completed_quest_titles.append(quest['title'])
            # Optionally: award a generic "Quest Master" badge or specific quest badges
            # check_for_levelup(user_progress, gamification_settings) # XP was added
        else:
            new_active_quests.append(quest) # Keep it in active if not completed or expired

    user_progress['activeQuests'] = new_active_quests
    user_progress['completedQuests'] = list(set(completed_quests_store)) # Ensure unique
    return completed_quest_titles

# --- Leaderboard Data Update ---
def update_leaderboard_data(user_doc_data):
    """Updates the denormalized leaderboardData field in the user document."""
    if 'progress' not in user_doc_data:
        user_doc_data['progress'] = {} # ensure progress exists
        
    progress = user_doc_data['progress']
    
    if 'leaderboardData' not in user_doc_data:
        user_doc_data['leaderboardData'] = {}
        
    user_doc_data['leaderboardData']['username'] = user_doc_data.get('username', 'Anonymous')
    # Ensure totalXp exists (cumulative) using leveling config if available
    total_xp = progress.get('totalXp')
    if total_xp is None or total_xp < 0:
        base = 100
        level = progress.get('level', 1)
        cumulative_prev = base * (level-1) * level // 2
        total_xp = cumulative_prev + progress.get('xp', 0)
        progress['totalXp'] = total_xp

    user_doc_data['leaderboardData']['totalXp'] = total_xp
    user_doc_data['leaderboardData']['currentStreak'] = progress.get('streak', 0)
    # Add other fields if needed for leaderboards, like level
    user_doc_data['leaderboardData']['level'] = progress.get('level', 1)

    return user_doc_data # Return the modified document data 