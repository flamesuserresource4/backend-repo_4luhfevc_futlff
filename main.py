import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Literal, Any, Dict

from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents

# ------------------ Security / Auth ------------------
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# ------------------ Helpers ------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    password: str


class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    phone: Optional[str] = None
    role: Literal["user", "admin"] = "user"
    blocked: bool = False


class UserUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    password: Optional[str] = None


class BotCreate(BaseModel):
    title: str
    description: str
    image_url: Optional[str] = None
    tags: List[str] = []
    is_paid: bool = False
    price: float = 0.0
    file_url: Optional[str] = None


class BotPublic(BaseModel):
    id: str
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


class HostingRequestCreate(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    message: str


class HostingRequestPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    mobile: str
    message: str
    user_id: Optional[str] = None
    status: Literal["new", "contacted", "closed"] = "new"
    admin_note: Optional[str] = None


class NoticeCreate(BaseModel):
    title: str
    message: str
    user_id: Optional[str] = None


class NoticePublic(BaseModel):
    id: str
    title: str
    message: str
    user_id: Optional[str] = None
    read: bool = False


class RazorpaySettings(BaseModel):
    key_id: str
    key_secret: str
    mode: Literal["sandbox", "live"] = "sandbox"


class PaymentCreate(BaseModel):
    bot_id: str


class PaymentConfirm(BaseModel):
    bot_id: str
    razorpay_order_id: Optional[str] = None
    razorpay_payment_id: Optional[str] = None
    amount: float
    currency: str = "INR"
    status: Literal["success", "failed"] = "success"


# Convert dict from Mongo to safe dict

def doc_to_public(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception
    if user.get("blocked"):
        raise HTTPException(status_code=403, detail="User is blocked")
    return user


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


app = FastAPI(title="Bot Hosting Platform API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"message": "Bot Hosting Platform API"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available" if db is None else "✅ Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["collections"] = db.list_collection_names()
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:80]}"
    return response


# ------------------ Auth ------------------
@app.post("/auth/signup", response_model=UserPublic)
def signup(payload: UserCreate):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    doc = {
        "name": payload.name,
        "email": payload.email,
        "phone": payload.phone,
        "password_hash": hash_password(payload.password),
        "role": "user",
        "blocked": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(doc)
    return UserPublic(id=str(result.inserted_id), name=doc["name"], email=doc["email"], phone=doc["phone"], role="user", blocked=False)


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db["user"].find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if user.get("blocked"):
        raise HTTPException(status_code=403, detail="User is blocked")
    token = create_access_token({"sub": str(user["_id"]), "role": user.get("role", "user")})
    return Token(access_token=token)


@app.get("/auth/me", response_model=UserPublic)
def me(user: dict = Depends(get_current_user)):
    return UserPublic(id=str(user["_id"]), name=user["name"], email=user["email"], phone=user.get("phone"), role=user.get("role", "user"), blocked=user.get("blocked", False))


@app.put("/users/me", response_model=UserPublic)
def update_me(payload: UserUpdate, user: dict = Depends(get_current_user)):
    updates: Dict[str, Any] = {}
    if payload.name is not None:
        updates["name"] = payload.name
    if payload.phone is not None:
        updates["phone"] = payload.phone
    if payload.password:
        updates["password_hash"] = hash_password(payload.password)
    if not updates:
        return UserPublic(id=str(user["_id"]), name=user["name"], email=user["email"], phone=user.get("phone"), role=user.get("role", "user"), blocked=user.get("blocked", False))
    updates["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": ObjectId(user["_id"])}, {"$set": updates})
    new_user = db["user"].find_one({"_id": ObjectId(user["_id"])})
    return UserPublic(id=str(new_user["_id"]), name=new_user["name"], email=new_user["email"], phone=new_user.get("phone"), role=new_user.get("role", "user"), blocked=new_user.get("blocked", False))


# ------------------ Bots ------------------
@app.post("/bots", response_model=BotPublic)
def create_bot(payload: BotCreate, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({
        "owner_id": str(user["_id"]),
        "approved": user.get("role") == "admin",  # auto-approve if admin
        "hosting_id": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    })
    res = db["bot"].insert_one(doc)
    created = db["bot"].find_one({"_id": res.inserted_id})
    return BotPublic(**doc_to_public(created))


@app.get("/bots", response_model=List[BotPublic])
def list_bots(q: Optional[str] = None, tag: Optional[str] = None, paid: Optional[bool] = None, limit: int = 50):
    query: Dict[str, Any] = {"approved": True}
    if q:
        query["$or"] = [
            {"title": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
        ]
    if tag:
        query["tags"] = tag
    if paid is not None:
        query["is_paid"] = paid
    cursor = db["bot"].find(query).sort("created_at", -1).limit(limit)
    return [BotPublic(**doc_to_public(d)) for d in cursor]


@app.get("/bots/{bot_id}", response_model=BotPublic)
def get_bot(bot_id: str):
    bot = db["bot"].find_one({"_id": ObjectId(bot_id)})
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    return BotPublic(**doc_to_public(bot))


@app.put("/bots/{bot_id}", response_model=BotPublic)
def update_bot(bot_id: str, payload: BotCreate, user: dict = Depends(get_current_user)):
    bot = db["bot"].find_one({"_id": ObjectId(bot_id)})
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    if str(bot.get("owner_id")) != str(user["_id"]) and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    updates = payload.model_dump()
    updates["updated_at"] = datetime.now(timezone.utc)
    db["bot"].update_one({"_id": ObjectId(bot_id)}, {"$set": updates})
    bot = db["bot"].find_one({"_id": ObjectId(bot_id)})
    return BotPublic(**doc_to_public(bot))


@app.delete("/bots/{bot_id}")
def delete_bot(bot_id: str, user: dict = Depends(get_current_user)):
    bot = db["bot"].find_one({"_id": ObjectId(bot_id)})
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    if str(bot.get("owner_id")) != str(user["_id"]) and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not allowed")
    db["bot"].delete_one({"_id": ObjectId(bot_id)})
    return {"ok": True}


@app.post("/bots/{bot_id}/approve")
def approve_bot(bot_id: str, approve: bool = Body(True), admin: dict = Depends(require_admin)):
    db["bot"].update_one({"_id": ObjectId(bot_id)}, {"$set": {"approved": bool(approve)}})
    return {"ok": True}


@app.post("/bots/{bot_id}/set-hosting-id")
def set_hosting_id(bot_id: str, hosting_id: Optional[str] = Body(None), admin: dict = Depends(require_admin)):
    hid = hosting_id or f"HID-{ObjectId()!s}"[-8:]
    db["bot"].update_one({"_id": ObjectId(bot_id)}, {"$set": {"hosting_id": hid}})
    return {"ok": True, "hosting_id": hid}


# ------------------ Saved Bots ------------------
@app.post("/bots/{bot_id}/save")
def toggle_save(bot_id: str, user: dict = Depends(get_current_user)):
    existing = db["savedbot"].find_one({"user_id": str(user["_id"]), "bot_id": bot_id})
    if existing:
        db["savedbot"].delete_one({"_id": existing["_id"]})
        return {"saved": False}
    create_document("savedbot", {"user_id": str(user["_id"]), "bot_id": bot_id})
    return {"saved": True}


@app.get("/users/me/saved", response_model=List[BotPublic])
def my_saved(user: dict = Depends(get_current_user)):
    links = list(db["savedbot"].find({"user_id": str(user["_id"])}) )
    bot_ids = [ObjectId(l["bot_id"]) for l in links]
    bots = list(db["bot"].find({"_id": {"$in": bot_ids}})) if bot_ids else []
    return [BotPublic(**doc_to_public(b)) for b in bots]


# ------------------ Hosting Requests ------------------
@app.post("/hosting-requests", response_model=HostingRequestPublic)
def create_hosting_request(payload: HostingRequestCreate, user: dict = Depends(get_current_user)):
    doc = payload.model_dump()
    doc.update({"user_id": str(user["_id"]), "status": "new", "admin_note": None})
    rid = create_document("hostingrequest", doc)
    created = db["hostingrequest"].find_one({"_id": ObjectId(rid)})
    d = doc_to_public(created)
    return HostingRequestPublic(**d)


@app.get("/admin/hosting-requests", response_model=List[HostingRequestPublic])
def list_hosting_requests(_: dict = Depends(require_admin)):
    rows = db["hostingrequest"].find().sort("created_at", -1)
    return [HostingRequestPublic(**doc_to_public(r)) for r in rows]


class HostingRequestUpdate(BaseModel):
    status: Optional[Literal["new", "contacted", "closed"]] = None
    admin_note: Optional[str] = None


@app.patch("/admin/hosting-requests/{req_id}")
def update_hosting_request(req_id: str, payload: HostingRequestUpdate, _: dict = Depends(require_admin)):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return {"ok": True}
    updates["updated_at"] = datetime.now(timezone.utc)
    db["hostingrequest"].update_one({"_id": ObjectId(req_id)}, {"$set": updates})
    return {"ok": True}


# ------------------ Notices ------------------
@app.get("/notices", response_model=List[NoticePublic])
def list_notices(user: dict = Depends(get_current_user)):
    q = {"$or": [{"user_id": None}, {"user_id": str(user["_id"])}]}
    rows = db["notice"].find(q).sort("created_at", -1)
    result: List[NoticePublic] = []
    for r in rows:
        d = doc_to_public(r)
        read_by = d.get("read_by", []) or []
        result.append(NoticePublic(id=d["id"], title=d["title"], message=d["message"], user_id=d.get("user_id"), read=str(user["_id"]) in read_by))
    return result


@app.post("/notices")
def create_notice(payload: NoticeCreate, _: dict = Depends(require_admin)):
    doc = payload.model_dump()
    create_document("notice", {**doc, "read_by": []})
    return {"ok": True}


@app.post("/notices/{notice_id}/read")
def mark_notice_read(notice_id: str, user: dict = Depends(get_current_user)):
    db["notice"].update_one({"_id": ObjectId(notice_id)}, {"$addToSet": {"read_by": str(user["_id"])}})
    return {"ok": True}


# ------------------ Payments (Razorpay placeholder) ------------------
@app.get("/admin/razorpay-settings", response_model=RazorpaySettings)
def get_razorpay_settings(_: dict = Depends(require_admin)):
    s = db["razorpaysettings"].find_one() or {"key_id": "rzp_test_xxx", "key_secret": "secret", "mode": "sandbox"}
    return RazorpaySettings(**doc_to_public(s))


@app.put("/admin/razorpay-settings", response_model=RazorpaySettings)
def put_razorpay_settings(payload: RazorpaySettings, _: dict = Depends(require_admin)):
    db["razorpaysettings"].delete_many({})
    create_document("razorpaysettings", payload)
    s = db["razorpaysettings"].find_one()
    return RazorpaySettings(**doc_to_public(s))


@app.get("/payments/keys")
def public_keys():
    s = db["razorpaysettings"].find_one() or {"key_id": "rzp_test_xxx", "key_secret": "secret", "mode": "sandbox"}
    return {"key_id": s.get("key_id"), "mode": s.get("mode", "sandbox")}


@app.post("/payments/create-order")
def create_order(payload: PaymentCreate, user: dict = Depends(get_current_user)):
    bot = db["bot"].find_one({"_id": ObjectId(payload.bot_id)})
    if not bot:
        raise HTTPException(status_code=404, detail="Bot not found")
    if not bot.get("is_paid"):
        raise HTTPException(status_code=400, detail="Bot is free")
    amount = float(bot.get("price", 0))
    order_id = f"order_{ObjectId()}"
    # Create transaction with status created
    create_document("transaction", {
        "user_id": str(user["_id"]),
        "bot_id": payload.bot_id,
        "amount": amount,
        "currency": "INR",
        "razorpay_order_id": order_id,
        "status": "created",
    })
    return {"order_id": order_id, "amount": amount, "currency": "INR"}


@app.post("/payments/confirm")
def confirm_payment(payload: PaymentConfirm, user: dict = Depends(get_current_user)):
    tx = db["transaction"].find_one({"razorpay_order_id": payload.razorpay_order_id, "user_id": str(user["_id"]), "bot_id": payload.bot_id})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    new_status = "success" if payload.status == "success" else "failed"
    db["transaction"].update_one({"_id": tx["_id"]}, {"$set": {
        "razorpay_payment_id": payload.razorpay_payment_id,
        "status": new_status,
        "updated_at": datetime.now(timezone.utc)
    }})
    if new_status == "success":
        # Unlock bot -> add to saved list
        if not db["savedbot"].find_one({"user_id": str(user["_id"]), "bot_id": payload.bot_id}):
            create_document("savedbot", {"user_id": str(user["_id"]), "bot_id": payload.bot_id})
    return {"ok": True, "status": new_status}


# ------------------ Admin: Users and Bots & Metrics ------------------
@app.get("/admin/metrics")
def metrics(_: dict = Depends(require_admin)):
    total_users = db["user"].count_documents({})
    total_bots = db["bot"].count_documents({})
    total_revenue = sum([float(t.get("amount", 0)) for t in db["transaction"].find({"status": "success"})])
    pending_hosting = db["hostingrequest"].count_documents({"status": "new"})
    pending_bot_approvals = db["bot"].count_documents({"approved": False})
    return {
        "total_users": total_users,
        "total_bots": total_bots,
        "total_revenue": total_revenue,
        "pending_hosting_requests": pending_hosting,
        "pending_bot_approvals": pending_bot_approvals,
    }


@app.get("/admin/users")
def list_users(_: dict = Depends(require_admin)):
    rows = db["user"].find().sort("created_at", -1)
    out = []
    for r in rows:
        d = doc_to_public(r)
        d.pop("password_hash", None)
        out.append(d)
    return out


class UserAdminUpdate(BaseModel):
    blocked: Optional[bool] = None
    role: Optional[Literal["user", "admin"]] = None


@app.patch("/admin/users/{user_id}")
def admin_update_user(user_id: str, payload: UserAdminUpdate, _: dict = Depends(require_admin)):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return {"ok": True}
    db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": updates})
    return {"ok": True}


@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, _: dict = Depends(require_admin)):
    db["user"].delete_one({"_id": ObjectId(user_id)})
    return {"ok": True}


@app.get("/admin/bots")
def admin_list_bots(_: dict = Depends(require_admin)):
    return [doc_to_public(b) for b in db["bot"].find().sort("created_at", -1)]


# File uploads placeholder endpoint (stores only metadata in this demo)
@app.post("/admin/bots/upload")
def upload_bot_file(file: UploadFile = File(...), image: Optional[UploadFile] = None, _: dict = Depends(require_admin)):
    # In a real system, upload to object storage and return URLs
    return {"file_url": f"/uploads/{file.filename}", "image_url": f"/uploads/{image.filename}" if image else None}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
