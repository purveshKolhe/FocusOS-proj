# FocusOS

A gamified study platform with real‑time rooms and an AI study assistant.

Created and maintained by **Purvesh Kolhe**  
Initial concept, design, and codebase built in October 2025.  
This is a private project. DO NOT copy.

## Tech Stack
- **Backend**: Flask, Flask‑SocketIO (threading mode)
- **Auth & DB**: Firebase Admin SDK (Auth, Firestore)
- **AI**: Google GenAI SDK (`google-genai`) – Gemini 2.5 Flash Lite
- **Frontend**: Jinja2 templates, Tailwind CSS, Vanilla JS

## Prerequisites
- Python 3.10+ (tested on 3.12)
- A Firebase project with a service account key
- A Gemini API key from Google AI Studio

## Setup
1) Install dependencies
```bash
pip install -r requirements.txt
```

2) Firebase service account
- In Firebase Console → Project Settings → Service Accounts → Generate new private key.
- Save as `serviceAccountKey.json` in the project root (`FocusOS-proj/`).

3) Environment variables
Set your Gemini key (do not commit secrets):
```bash
# Windows PowerShell
$env:GEMINI_API_KEY = "<your-api-key>"

# macOS/Linux
export GEMINI_API_KEY="<your-api-key>"
```
Optionally use a `.env` file for other settings (Flask secret, firebase service account key[json] etc.).

## Run
```bash
python app.py
```
The app starts the Flask dev server and Socket.IO using threading async mode.

## Features
- **Auth**: Firebase email/password login
- **Rooms**: Collaborative study rooms with shared Pomodoro timer
- **AI Assistant (Daphinix)**: Text and image chat via Gemini 2.5 Flash Lite
- **Gamification**: XP, levels, quests, badges, leaderboard
- **Productivity**: Todos, focus mode, ambient sounds, customizable backgrounds

## Configuration Notes
- Place `serviceAccountKey.json` in the project root.
- Ensure `GEMINI_API_KEY` is set before using AI features.
- SocketIO is configured with `async_mode='threading'` for wide OS compatibility. 

# IMPORTANT NOTE: If testing this project, use async_mode = "eventlet" on environments like render web service and async_mode = "threading" on local PC. Why?:
I had run into a lot of problems while running this and after 2 days of doing stuff, I realised that it is what it is. I don't know how that works and why that works, but it does!

## Migration Note (AI SDK)
- Migrated from deprecated `google.generativeai` to the new `google-genai` SDK.
- Requests now use `genai.Client()` and `client.models.generate_content(...)` with
  `genai.types.GenerateContentConfig` for safety and system instructions.

## Security
- Do not commit secrets (`serviceAccountKey.json`, API keys).
- Rotate keys immediately if exposed.

## License / Usage
FocusOS is a proprietary closed‑source project created solely by Purvesh Kolhe. No part of this project may be used without written permission.
