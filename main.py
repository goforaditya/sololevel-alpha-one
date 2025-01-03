from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi import Body
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import Optional, Union, List, Dict
from pydantic import BaseModel
from openai import OpenAI
import logging
import os
import hashlib
import time
import markdown
import bleach
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("app.log")]
)
logger = logging.getLogger(__name__)

from database import engine, get_db, Base
from models import User, Entry, Activity, Comment
from auth import (
    get_password_hash, 
    verify_password, 
    create_access_token, 
    get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

# Rate limiting configuration
post_rate_limits = defaultdict(list)
RATE_LIMIT_POSTS = 5  # Maximum posts per hour
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds

def check_rate_limit(ip_address: str) -> bool:
    current_time = time.time()
    # Clean up old timestamps
    post_rate_limits[ip_address] = [
        t for t in post_rate_limits[ip_address] 
        if current_time - t < RATE_LIMIT_WINDOW
    ]
    if len(post_rate_limits[ip_address]) >= RATE_LIMIT_POSTS:
        return False
    post_rate_limits[ip_address].append(current_time)
    return True

def render_markdown(content: str) -> str:
    allowed_tags = bleach.sanitizer.ALLOWED_TAGS + [
        'p', 'br', 'blockquote', 'pre', 'code', 
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li', 'hr', 'em', 'strong'
    ]
    allowed_attrs = {
        **bleach.sanitizer.ALLOWED_ATTRIBUTES,
        'code': ['class'],
        'pre': ['class']
    }
    html_content = markdown.markdown(
        content,
        extensions=['fenced_code', 'tables', 'nl2br']
    )
    return bleach.clean(html_content, tags=allowed_tags, attributes=allowed_attrs)

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.filters['render_markdown'] = render_markdown

class ChatMessage(BaseModel):
    role: str
    content: str

@app.get("/", response_class=HTMLResponse)
async def home(
    request: Request, 
    current_user: Union[User, None] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_entries = []
    public_entries = (
        db.query(Entry)
        .filter(Entry.is_public == True)
        .order_by(Entry.created_at.desc())
        .limit(10)
        .all()
    )
    
    if current_user:
        user_entries = (
            db.query(Entry)
            .filter(Entry.user_id == current_user.id)
            .order_by(Entry.created_at.desc())
            .all()
        )
    
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "user": current_user,
            "user_entries": user_entries,
            "public_entries": public_entries
        }
    )

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response

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
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    response = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        secure=True,  # Only send over HTTPS
        samesite='lax'  # Protect against CSRF
    )
    return response

@app.post("/entries")
async def create_entry(
    request: Request,
    content: str = Form(...),
    is_public: bool = Form(False),
    current_user: Union[User, None] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = request.client.host
    
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many posts. Please wait before posting again."
        )
    
    if len(content) > 5000:
        raise HTTPException(
            status_code=400,
            detail="Content too long. Maximum 5000 characters."
        )
    
    # Create anonymous ID if no user
    anonymous_user_id = None
    is_anonymous = False
    if not current_user:
        is_anonymous = True
        unique_string = f"{client_ip}:{time.time()}"
        anonymous_user_id = hashlib.sha256(unique_string.encode()).hexdigest()[:12]
    
    entry = Entry(
        content=content,
        is_public=is_public,
        user_id=current_user.id if current_user else None,
        anonymous_user_id=anonymous_user_id,
        is_anonymous=is_anonymous
    )
    
    db.add(entry)
    db.commit()
    
    # Generate AI suggestions for logged-in users
    if current_user:
        try:
            client = OpenAI()
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a helpful assistant that suggests 3 concrete, actionable activities based on journal entries. Keep suggestions specific and measurable."
                    },
                    {"role": "user", "content": content}
                ]
            )
            
            suggestions = response.choices[0].message.content.split('\n')
            for suggestion in suggestions:
                if suggestion.strip():
                    activity = Activity(
                        description=suggestion.strip(),
                        user_id=current_user.id,
                        entry_id=entry.id
                    )
                    db.add(activity)
            
            db.commit()
            
        except Exception as e:
            logger.error(f"Error generating suggestions: {str(e)}")
            # Don't fail the entry creation if AI suggestions fail
    
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/chat/entry")
async def generate_entry(
    messages: List[ChatMessage] = Body(...),
    current_user: Union[User, None] = Depends(get_current_user)
):
    logger.info(f"Received chat entry generation request from: {current_user.username if current_user else 'anonymous'}")
    
    try:
        client = OpenAI()
        formatted_messages = [
            {
                "role": "system",
                "content": "You are a helpful assistant that helps users journal their day. Convert their chat messages into a well-formatted journal entry."
            }
        ]
        formatted_messages.extend([{"role": msg.role, "content": msg.content} for msg in messages])
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=formatted_messages
        )
        
        return JSONResponse(content=response.choices[0].message.content)
        
    except Exception as e:
        logger.error(f"Error generating entry: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate entry: {str(e)}"
        )

@app.post("/entries/{entry_id}/comments")
async def create_comment(
    request: Request,
    entry_id: int,
    content: str = Form(...),
    current_user: Union[User, None] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if entry exists
    entry = db.query(Entry).filter(Entry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
        
    # Create anonymous ID if no user
    anonymous_user_id = None
    is_anonymous = False
    if not current_user:
        is_anonymous = True
        client_ip = request.client.host
        unique_string = f"{client_ip}:{time.time()}"
        anonymous_user_id = hashlib.sha256(unique_string.encode()).hexdigest()[:12]

    comment = Comment(
        content=content,
        entry_id=entry_id,
        user_id=current_user.id if current_user else None,
        anonymous_user_id=anonymous_user_id,
        is_anonymous=is_anonymous
    )
    
    db.add(comment)
    db.commit()
    
    return RedirectResponse(
        url=f"/entries/{entry_id}",
        status_code=status.HTTP_303_SEE_OTHER
    )

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

@app.post("/api/entries")
async def create_entry_api(
    request: Request,
    messages: List[ChatMessage] = Body(...),
    current_user: Union[User, None] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Get client IP for rate limiting
        client_ip = request.client.host
        
        if not check_rate_limit(client_ip):
            raise HTTPException(
                status_code=429,
                detail="Too many posts. Please wait before posting again."
            )
        
        # Format the content from chat messages
        content = "\n\n".join([
            msg.content for msg in messages 
            if msg.role == "user"
        ])
        
        if len(content) > 5000:
            raise HTTPException(
                status_code=400,
                detail="Content too long. Maximum 5000 characters."
            )
        
        # Create anonymous ID if no user
        anonymous_user_id = None
        is_anonymous = False
        if not current_user:
            is_anonymous = True
            unique_string = f"{client_ip}:{time.time()}"
            anonymous_user_id = hashlib.sha256(unique_string.encode()).hexdigest()[:12]
        
        # Create the entry
        entry = Entry(
            content=content,
            is_public=False,  # Default to private for chat-created entries
            user_id=current_user.id if current_user else None,
            anonymous_user_id=anonymous_user_id,
            is_anonymous=is_anonymous
        )
        
        db.add(entry)
        db.commit()
        db.refresh(entry)
        
        # Generate AI suggestions for logged-in users
        activities = []
        if current_user:
            try:
                client = OpenAI()
                response = client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a helpful assistant that suggests 3 concrete, actionable activities based on journal entries. Keep suggestions specific and measurable."
                        },
                        {"role": "user", "content": content}
                    ]
                )
                
                suggestions = response.choices[0].message.content.split('\n')
                for suggestion in suggestions:
                    if suggestion.strip():
                        activity = Activity(
                            description=suggestion.strip(),
                            user_id=current_user.id,
                            entry_id=entry.id
                        )
                        db.add(activity)
                        activities.append(activity)
                
                db.commit()
                
            except Exception as e:
                logger.error(f"Error generating suggestions: {str(e)}")
        
        # Return the created entry with activities
        return {
            "id": entry.id,
            "content": entry.content,
            "created_at": entry.created_at.isoformat(),
            "is_public": entry.is_public,
            "activities": [
                {
                    "id": activity.id,
                    "description": activity.description
                } for activity in activities
            ] if activities else []
        }
        
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error creating entry: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create entry: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)