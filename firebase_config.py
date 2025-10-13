import firebase_admin
from firebase_admin import credentials, firestore
import os
from pathlib import Path
import json

def initialize_firebase():
    try:
        if not firebase_admin._apps:
            try:
                # Try environment variable first
                service_account_info = json.loads(os.environ["FIREBASE_SERVICE_ACCOUNT"])
                cred = credentials.Certificate(service_account_info)
            except (KeyError, json.JSONDecodeError):
                # Fallback to local file
                service_account_path = Path(__file__).parent / "serviceAccountKey.json"
                cred = credentials.Certificate(str(service_account_path))
            firebase_admin.initialize_app(cred)
        return firestore.client()
    except Exception as e:
        print(f"Error initializing Firebase: {e}")
        raise

def get_user_data(username):
    db = firestore.client()
    user_ref = db.collection('users').document(username)
    user_doc = user_ref.get()
    return user_doc.to_dict() if user_doc.exists else None

def save_user_data(username, data):
    try:
        db = firestore.client()
        user_ref = db.collection('users').document(username)
        user_ref.set(data, merge=True)
        return True
    except Exception as e:
        print(f"Error saving user data: {e}")
        return False

def get_chat_history(username):
    db = firestore.client()
    chat_ref = db.collection('chat_history').document(username)
    chat_doc = chat_ref.get()
    return chat_doc.to_dict() if chat_doc.exists else {'messages': []}

def save_chat_history(username, messages):
    try:
        db = firestore.client()
        chat_ref = db.collection('chat_history').document(username)
        chat_ref.set({'messages': messages}, merge=True)
        return True
    except Exception as e:
        print(f"Error saving chat history: {e}")
        return False

def get_todo_list(username):
    db = firestore.client()
    todo_ref = db.collection('todo_lists').document(username)
    todo_doc = todo_ref.get()
    return todo_doc.to_dict() if todo_doc.exists else {'todos': []}

def save_todo_list(username, data):
    try:
        db = firestore.client()
        todo_ref = db.collection('todo_lists').document(username)
        todo_ref.set(data, merge=True)
        return True
    except Exception as e:
        print(f"Error saving todo list: {e}")
        return False 