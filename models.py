from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    entries = relationship("Entry", back_populates="user")
    activities = relationship("Activity", back_populates="user")
    comments = relationship("Comment", back_populates="user")

class Entry(Base):
    __tablename__ = "entries"
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text)
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))
    
    user = relationship("User", back_populates="entries")
    activities = relationship("Activity", back_populates="entry")
    anonymous_user_id = Column(String, nullable=True)  # Store hashed IP or session ID
    is_anonymous = Column(Boolean, default=False)
    comments = relationship("Comment", back_populates="entry")

class Activity(Base):
    __tablename__ = "activities"
    
    id = Column(Integer, primary_key=True, index=True)
    description = Column(Text)
    progress = Column(Float, default=0.0)  # 0-100%
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))
    entry_id = Column(Integer, ForeignKey("entries.id"))
    
    user = relationship("User", back_populates="activities")
    entry = relationship("Entry", back_populates="activities")

class Comment(Base):
    __tablename__ = "comments"
    
    id = Column(Integer, primary_key=True, index=True)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    entry_id = Column(Integer, ForeignKey("entries.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    anonymous_user_id = Column(String, nullable=True)
    is_anonymous = Column(Boolean, default=False)
    
    entry = relationship("Entry", back_populates="comments")
    user = relationship("User", back_populates="comments")