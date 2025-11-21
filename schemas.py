"""
Database Schemas for Bot Hosting Platform

Each Pydantic model represents a MongoDB collection.
Collection name = lowercase of class name.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Literal

class User(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None
    password_hash: str
    role: Literal["user", "admin"] = "user"
    blocked: bool = False

class Bot(BaseModel):
    title: str
    description: str
    image_url: Optional[str] = None
    tags: List[str] = []
    is_paid: bool = False
    price: float = 0.0
    owner_id: Optional[str] = None
    approved: bool = False
    hosting_id: Optional[str] = None
    file_url: Optional[str] = None

class SavedBot(BaseModel):
    user_id: str
    bot_id: str

class Hostingrequest(BaseModel):
    name: str
    email: str
    mobile: str
    message: str
    user_id: Optional[str] = None
    status: Literal["new", "contacted", "closed"] = "new"
    admin_note: Optional[str] = None

class Notice(BaseModel):
    title: str
    message: str
    user_id: Optional[str] = None  # None means broadcast
    read_by: List[str] = []

class Transaction(BaseModel):
    user_id: str
    bot_id: str
    amount: float
    currency: str = "INR"
    razorpay_order_id: Optional[str] = None
    razorpay_payment_id: Optional[str] = None
    status: Literal["created", "success", "failed"] = "created"

class Razorpaysettings(BaseModel):
    key_id: str
    key_secret: str
    mode: Literal["sandbox", "live"] = "sandbox"
