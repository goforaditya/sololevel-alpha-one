from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi import Body
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import Optional, Union
from openai import OpenAI
import os
# Add at the top with other imports
import time
# from recaptcha import verify_recaptcha

from database import engine, get_db, Base
from models import User, Entry, Activity
from auth import (get_password_hash, verify_password, 
                 create_access_token, get_current_user,
                 ACCESS_TOKEN_EXPIRE_MINUTES)

# Add these at the top with other imports
from collections import defaultdict
post_rate_limits = defaultdict(list)  # Store post timestamps per IP
RATE_LIMIT_POSTS = 5  # Maximum posts per hour
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds

# Add this function for rate limiting
def check_rate_limit(ip_address: str) -> bool:
    current_time = time.time()
    if ip_address not in post_rate_limits:
        post_rate_limits[ip_address] = []
    post_rate_limits[ip_address] = [
        t for t in post_rate_limits[ip_address] 
        if current_time - t < RATE_LIMIT_WINDOW
    ]
    if len(post_rate_limits[ip_address]) >= RATE_LIMIT_POSTS:
        return False
    post_rate_limits[ip_address].append(current_time)
    return True

def render_markdown(content: str) -> str:
    allowed_tags = bleach.sanitizer.ALLOWED_TAGS + ['p', 'br', 'blockquote', 'pre', 'code']
    allowed_attrs = bleach.sanitizer.ALLOWED_ATTRIBUTES
    html_content = markdown.markdown(content)
    return bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attrs)
  
# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")
templates.env.filters['render_markdown'] = render_markdown

# OpenAI setup
openai.api_key = os.getenv("OPENAI_API_KEY")

@app.get("/", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
async def home(request: Request, current_user: Union[User, None] = Depends(get_current_user)):
    db = next(get_db())
    user_entries = []
    public_entries = db.query(Entry).filter(Entry.is_public == True).order_by(Entry.created_at.desc()).limit(10).all()
    
    if current_user:
        user_entries = db.query(Entry).filter(Entry.user_id == current_user.id).order_by(Entry.created_at.desc()).all()
    
    return templates.TemplateResponse(
        "home.html", 
        {
            "request": request, 
            "user": current_user, 
            "user_entries": user_entries,
            "public_entries": public_entries
        }
    )

# Login route
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        "login.html", 
        {"request": request}
    )

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response
  
# Login form processing
@app.post("/token")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True
    )
    return response

# Registration routes
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(
        "register.html", 
        {"request": request}
    )

@app.post("/register")
async def register(
    request: Request,
    email: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if user exists
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    hashed_password = get_password_hash(password)
    user = User(email=email, username=username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/entries")
async def create_entry(
    request: Request,
    content: str = Form(...),
    is_public: bool = Form(False),
    current_user: User = Depends(get_current_user) or None,
    db: Session = Depends(get_db)
):
    # Get client IP
    client_ip = request.client.host
    
    # Check rate limit
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many posts. Please wait before posting again."
        )
    
    # Basic content moderation
    if len(content) > 5000:  # Limit post length
        raise HTTPException(
            status_code=400,
            detail="Content too long. Maximum 5000 characters."
        )
    
    # Create anonymous ID if no user
    anonymous_user_id = None
    is_anonymous = False
    if not current_user:
        is_anonymous = True
        # Create a unique ID based on IP and timestamp
        unique_string = f"{client_ip}:{time.time()}"
        anonymous_user_id = hashlib.sha256(unique_string.encode()).hexdigest()[:12]
    
    # Create entry
    entry = Entry(
        content=content,
        is_public=is_public,
        user_id=current_user.id if current_user else None,
        anonymous_user_id=anonymous_user_id,
        is_anonymous=is_anonymous
    )
    
    db.add(entry)
    db.commit()
    
    # Only generate suggestions for logged-in users
    if current_user:
        # Generate activity suggestions using OpenAI
        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4o",
            store=True,
            messages=[
                {"role": "system", "content": "You are a helpful assistant that suggests 3 concrete, actionable activities based on journal entries. Keep suggestions specific and measurable."},
                {"role": "user", "content": content}]
        )
        print(response)
        suggestions = response.choices[0].message.content.split('\n')
        # Your existing OpenAI suggestion code here
        # Create activities from suggestions
        for suggestion in suggestions:
            if suggestion.strip():
                activity = Activity(
                    description=suggestion,
                    user_id=current_user.id,
                    entry_id=entry.id
                )
                db.add(activity)
        
        db.commit()

    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

# @app.post("/entries")
# async def create_entry(
#     content: str = Form(...),
#     is_public: bool = Form(False),
#     current_user: User = Depends(get_current_user),
#     db: Session = Depends(get_db)
# ):
#     # Create entry
#     entry = Entry(content=content, is_public=is_public, user_id=current_user.id)
#     db.add(entry)
#     db.commit()
    
#     # Generate activity suggestions using OpenAI
#     response = openai.ChatCompletion.create(
#         model="gpt-4o-mini",
#         messages=[
#             {"role": "system", "content": "You are a helpful assistant that suggests 3 concrete, actionable activities based on journal entries. Keep suggestions specific and measurable."},
#             {"role": "user", "content": content}
#         ]
#     )
    
#     suggestions = response.choices[0].message.content.split('\n')
    
#     # Create activities from suggestions
#     for suggestion in suggestions:
#         if suggestion.strip():
#             activity = Activity(
#                 description=suggestion,
#                 user_id=current_user.id,
#                 entry_id=entry.id
#             )
#             db.add(activity)
    
#     db.commit()
#     return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/activities/{activity_id}/progress")
async def update_progress(
    activity_id: int,
    progress: float = Form(...),
    notes: str = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    activity = db.query(Activity).filter(
        Activity.id == activity_id,
        Activity.user_id == current_user.id
    ).first()
    
    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found")
    
    activity.progress = progress
    if notes:
        activity.notes = notes
    
    db.commit()
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/chat/entry")
async def generate_entry(
    request: Request,
    messages: list = Body(...),
    current_user: Union[User, None] = Depends(get_current_user)
):
    try:
        client = OpenAI()
        response = client.chat.completions.create(
            model="gpt-4o",
            store=True,
            messages=[
                {"role": "system", "content": "You are a helpful assistant that helps users journal their day. Convert their chat messages into a well-formatted journal entry."},
                *messages]
        )
        print(response)
        return {"entry": response.choices[0].message.content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
