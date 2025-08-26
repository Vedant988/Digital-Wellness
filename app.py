import os
import datetime
import base64
import json
import re
import random
from typing import Dict, List, Optional

# --- Pydantic for Settings Management ---
from pydantic_settings import BaseSettings
from pydantic import EmailStr

# --- FastAPI Imports ---
from fastapi import (
    FastAPI, Request, Form, Depends, HTTPException, status, UploadFile, File, Query
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm

# --- Security and Authentication Imports ---
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

# --- Database Imports (Motor for Async MongoDB) ---
import motor.motor_asyncio

# --- AI Service Imports ---
from groq import AsyncGroq

# --- Email Service Imports ---
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

# =============================================================================
# 1. CONFIGURATION (using Pydantic)
# =============================================================================
class Settings(BaseSettings):
    """Manages environment variables."""
    SECRET_KEY: str = "your-secret-key-here"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    MONGO_DETAILS: str = "mongodb://localhost:27017"
    GROQ_API_KEY: str = "your-groq-api-key"

    # --- Email Settings ---
    # IMPORTANT: Use a Google App Password if using Gmail.
    # https://support.google.com/accounts/answer/185833
    MAIL_USERNAME: str = "your-email@gmail.com"
    MAIL_PASSWORD: str = "your-google-app-password"
    MAIL_FROM: EmailStr = "your-email@gmail.com"
    MAIL_PORT: int = 587
    MAIL_SERVER: str = "smtp.gmail.com"
    MAIL_STARTTLS: bool = True
    MAIL_SSL_TLS: bool = False

    class Config:
        env_file = ".env"

settings = Settings()

# --- Password Hashing Context ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- FastAPI App Initialization ---
app = FastAPI(title="Digital Wellness Monitor")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- Email Configuration for fastapi-mail ---
conf = ConnectionConfig(
    MAIL_USERNAME = settings.MAIL_USERNAME,
    MAIL_PASSWORD = settings.MAIL_PASSWORD,
    MAIL_FROM = settings.MAIL_FROM,
    MAIL_PORT = settings.MAIL_PORT,
    MAIL_SERVER = settings.MAIL_SERVER,
    MAIL_STARTTLS = settings.MAIL_STARTTLS,
    MAIL_SSL_TLS = settings.MAIL_SSL_TLS,
    USE_CREDENTIALS = True,
    VALIDATE_CERTS = True
)

# =============================================================================
# 2. DATABASE SETUP
# =============================================================================
@app.on_event("startup")
async def startup_db_client():
    app.mongodb_client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGO_DETAILS)
    app.mongodb = app.mongodb_client.get_database("wellness_dbi")
    # Initialize Groq client on startup
    app.groq_client = AsyncGroq(api_key=settings.GROQ_API_KEY)

@app.on_event("shutdown")
async def shutdown_db_client():
    app.mongodb_client.close()

def get_user_collection():
    return app.mongodb.users

def get_screentime_collection():
    return app.mongodb.screentime

# =============================================================================
# 3. LIVE AI SERVICE (Groq API Implementation)
# =============================================================================
async def analyze_screenshot_with_groq(image_bytes: bytes) -> Dict:
    """
    Analyzes a screenshot using Groq's vision - "meta-llama/llama-4-maverick-17b-128e-instruct" model for validation and data extraction.
    """
    base64_image = base64.b64encode(image_bytes).decode("utf-8")
    current_year = datetime.datetime.now().year

    try:
        chat_completion = await app.groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert data extraction assistant. Your task is to analyze images of smartphone screen time reports and extract specific information in a structured JSON format. You must adhere strictly to the requested format and output only raw JSON."
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": f"""Analyze the attached screenshot.

First, determine if this is a valid 'Digital Wellbeing' (Android) or 'Screen Time' (iOS) report.
- If it is NOT a valid report, your response MUST BE ONLY the following JSON:
  {{"error": "Validation Failed: The uploaded image does not appear to be a valid screen time screenshot."}}

- If it IS a valid report, extract the following information:
  1. The date shown on the screen. Format it as 'day,month date'. If the year is not visible, assume the current year, {current_year}.
  2. The total screen time for that day. Express it as a string like 'Xh Ym'.
  3. The top 3 most used apps and their specific usage times.

Your response for a valid report MUST BE ONLY a single, clean JSON object in this exact format:
{{
  "date": "YYYY-MM-DD",
  "totalScreenTime": "Xh Ym",
  "topApps": [
    {{"appName": "AppName1", "timeUsed": "Xh Ym"}},
    {{"appName": "AppName2", "timeUsed": "Xh Ym"}},
    {{"appName": "AppName3", "timeUsed": "Xh Ym"}}
  ]
}}

Do not include any other text, explanations, or markdown formatting. Your entire output must be the raw JSON object."""
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/png;base64,{base64_image}"
                            },
                        },
                    ],
                },
            ],
            model="meta-llama/llama-4-maverick-17b-128e-instruct",
            temperature=0.0,
            max_tokens=1024,
        )
        
        response_text = chat_completion.choices[0].message.content
        data = json.loads(response_text)

        if "error" in data:
            raise ValueError(data["error"])

        if not all(k in data for k in ["date", "totalScreenTime", "topApps"]):
            raise ValueError("AI failed to return the data in the expected format.")

        return data

    except json.JSONDecodeError:
        raise ValueError("AI response was not valid JSON. Please try again.")
    except Exception as e:
        if isinstance(e, ValueError):
            raise e
        print(f"Groq API Error: {e}")
        raise Exception("An error occurred while communicating with the AI service.")

# =============================================================================
# 4. AUTHENTICATION & SECURITY
# =============================================================================
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return None

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except JWTError:
        return None
    
    user = await get_user_collection().find_one({"email": email, "is_verified": True})
    return user

async def get_current_user_required(request: Request):
    user = await get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": "/"},
        )
    return user

async def get_current_admin(request: Request):
    user = await get_current_user_required(request)
    if not user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# =============================================================================
# 5. UTILITY FUNCTIONS
# =============================================================================
def generate_otp() -> str:
    """Generates a 6-digit OTP."""
    return str(random.randint(100000, 999999))

async def send_otp_email(email: str, otp: str):
    """Sends the OTP to the user's email."""
    html = f"""
    <html>
        <body>
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2>Digital Wellness Monitor Verification</h2>
                <p>Hello,</p>
                <p>Thank you for registering. Please use the following verification code to complete your registration. The code is valid for 10 minutes.</p>
                <p style="font-size: 24px; font-weight: bold; letter-spacing: 2px; color: #333;">{otp}</p>
                <p>If you did not request this code, please ignore this email.</p>
                <hr>
                <p><small>This is an automated message. Please do not reply.</small></p>
            </div>
        </body>
    </html>
    """
    message = MessageSchema(
        subject="Your Verification Code",
        recipients=[email],
        body=html,
        subtype="html"
    )
    fm = FastMail(conf)
    await fm.send_message(message)

def parse_time_to_minutes(time_str: str) -> int:
    """Convert time string like '2h 30m' to minutes"""
    time_str = time_str.lower().replace(" ", "")
    hours = 0
    minutes = 0
    
    if 'h' in time_str:
        parts = time_str.split('h')
        try:
            hours = int(parts[0])
        except ValueError:
            hours = 0
        if len(parts) > 1 and 'm' in parts[1]:
            try:
                minutes = int(parts[1].replace('m', ''))
            except ValueError:
                minutes = 0
    elif 'm' in time_str:
        try:
            minutes = int(time_str.replace('m', ''))
        except ValueError:
            minutes = 0
    
    return hours * 60 + minutes

def minutes_to_time_str(minutes: int) -> str:
    """Convert minutes to time string like '2h 30m'"""
    hours = minutes // 60
    mins = minutes % 60
    if hours > 0 and mins > 0:
        return f"{hours}h {mins}m"
    elif hours > 0:
        return f"{hours}h"
    else:
        return f"{mins}m"

def extract_roll_number(email: str) -> str:
    """Extract roll number from email address"""
    match = re.search(r'([a-z]{2}\d{2}[a-z]{3}\d{3})', email.lower())
    return match.group(1) if match else ""

async def calculate_weekly_stats(user_email: str, target_week_start: datetime.date):
    """
    Calculate weekly statistics for a user with a full 7-day structure for robustness.
    The average is now dynamic based on the number of days logged.
    """
    week_end = target_week_start + datetime.timedelta(days=6)
    cursor = get_screentime_collection().find({
        "user_email": user_email,
        "date": {
            "$gte": target_week_start.strftime("%Y-%m-%d"),
            "$lte": week_end.strftime("%Y-%m-%d")
        }
    })
    entries = await cursor.to_list(length=None)
    entry_map = {entry["date"]: entry for entry in entries}
    total_minutes = 0
    daily_data = []

    for i in range(7):
        current_date = target_week_start + datetime.timedelta(days=i)
        date_str = current_date.strftime("%Y-%m-%d")
        entry = entry_map.get(date_str)
        minutes = 0
        if entry and "totalScreenTime" in entry:
            minutes = parse_time_to_minutes(entry.get("totalScreenTime", "0m"))
        total_minutes += minutes
        daily_data.append({
            "day": current_date.strftime("%a"),
            "date": date_str,
            "minutes": minutes
        })

    days_logged = len(entries)
    average_minutes = total_minutes // days_logged if days_logged > 0 else 0

    return {
        "average_minutes": average_minutes,
        "total_minutes": total_minutes,
        "days_logged": days_logged,
        "daily_data": daily_data
    }

async def get_student_attention_status(user_email: str):
    """Determine if a student needs attention based on criteria"""
    today = datetime.date.today()
    current_week_start = today - datetime.timedelta(days=today.weekday())
    
    current_week_stats = await calculate_weekly_stats(user_email, current_week_start)
    high_screen_time = current_week_stats["average_minutes"] > 480  # 8 hours
    
    seven_days_ago = today - datetime.timedelta(days=7)
    recent_entry = await get_screentime_collection().find_one({
        "user_email": user_email,
        "date": {"$gte": seven_days_ago.strftime("%Y-%m-%d")}
    })
    no_recent_submissions = recent_entry is None
    
    status = "normal"
    if high_screen_time:
        status = "high_screentime"
    elif no_recent_submissions:
        status = "no_submissions"
    
    return {
        "status": status,
        "weekly_average_minutes": current_week_stats["average_minutes"],
        "days_logged_this_week": current_week_stats["days_logged"]
    }

# =============================================================================
# 6. FRONTEND ROUTES (HTML Pages)
# =============================================================================
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, message: Optional[str] = Query(None), error: Optional[str] = Query(None)):
    return templates.TemplateResponse("login.html", {
        "request": request, 
        "message": message,
        "error": error
    })

@app.get("/dashboard", response_class=HTMLResponse)
async def view_dashboard(request: Request, user: dict = Depends(get_current_user_required), message: Optional[str] = Query(None), error: Optional[str] = Query(None)):
    cursor = get_screentime_collection().find({"user_email": user["email"]}).sort("date", -1)
    user_data = await cursor.to_list(length=100)
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user, "data": user_data,
        "message": message, "error": error
    })

@app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request, admin: dict = Depends(get_current_admin), search: Optional[str] = Query(None)):
    cursor = get_user_collection().find({"is_admin": {"$ne": True}, "is_verified": True})
    all_students = await cursor.to_list(length=None)
    students_to_process = []
    if search:
        search_lower = search.lower()
        for student in all_students:
            roll_number = extract_roll_number(student["email"])
            if search_lower in student["email"].lower() or search_lower in roll_number:
                students_to_process.append(student)
    else:
        students_to_process = all_students

    enhanced_students = []
    for student in students_to_process:
        attention_status = await get_student_attention_status(student["email"])
        enhanced_students.append({
            **student,
            "roll_number": extract_roll_number(student["email"]),
            "attention_status": attention_status["status"],
            "weekly_average_minutes": attention_status["weekly_average_minutes"],
            "days_logged_this_week": attention_status["days_logged_this_week"]
        })

    return templates.TemplateResponse("admin.html", {
        "request": request, "admin": admin, "students": enhanced_students,
        "search_query": search or ""
    })

@app.get("/admin/student/{student_email}", response_class=HTMLResponse)
async def view_student_data(request: Request, student_email: str, admin: dict = Depends(get_current_admin)):
    student = await get_user_collection().find_one({"email": student_email})
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    
    cursor = get_screentime_collection().find({"user_email": student_email}).sort("date", -1)
    student_data = await cursor.to_list(length=100)
    
    today = datetime.date.today()
    current_week_start = today - datetime.timedelta(days=today.weekday())
    
    weeks_data = []
    for week_offset in range(4):
        week_start = current_week_start - datetime.timedelta(days=7 * week_offset)
        week_stats = await calculate_weekly_stats(student_email, week_start)
        weeks_data.append({
            "week_start": week_start.strftime("%Y-%m-%d"),
            "week_label": f"Week {week_offset + 1}" if week_offset > 0 else "This Week",
            **week_stats
        })
    
    percentage_change = 0
    if len(weeks_data) >= 2 and weeks_data[1]["average_minutes"] > 0:
        current_avg = weeks_data[0]["average_minutes"]
        previous_avg = weeks_data[1]["average_minutes"]
        percentage_change = ((current_avg - previous_avg) / previous_avg) * 100
    
    return templates.TemplateResponse("student_detail.html", {
        "request": request, "admin": admin, "student": student,
        "student_roll": extract_roll_number(student["email"]),
        "data": student_data, "weeks_data": weeks_data,
        "percentage_change": round(percentage_change, 1)
    })

# =============================================================================
# 7. API & FORM ROUTES (Backend Logic)
# =============================================================================
@app.post("/initiate-registration")
async def initiate_registration(request: Request, email: str = Form(...)):
    if not email.endswith("@iiitn.ac.in"):
        return RedirectResponse(url="/?error=Registration failed: Email must be from the @iiitn.ac.in domain.", status_code=status.HTTP_303_SEE_OTHER)

    user_collection = get_user_collection()
    existing_user = await user_collection.find_one({"email": email})
    if existing_user and existing_user.get("is_verified"):
        return RedirectResponse(url="/?error=User with this email already exists.", status_code=status.HTTP_303_SEE_OTHER)

    otp = generate_otp()
    otp_hash = get_password_hash(otp)
    otp_expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)

    await user_collection.update_one(
        {"email": email},
        {"$set": {
            "email": email, "otp_hash": otp_hash, "otp_expires_at": otp_expires_at,
            "is_verified": False, "created_at": datetime.datetime.utcnow()
        }},
        upsert=True
    )

    try:
        await send_otp_email(email, otp)
    except Exception as e:
        print(f"Email sending failed: {e}")
        return RedirectResponse(url="/?error=Could not send verification email. Please try again.", status_code=status.HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse("verify.html", {
        "request": request, "email": email,
        "message": "A verification code has been sent to your email."
    })

@app.post("/complete-registration")
async def complete_registration(request: Request, email: str = Form(...), otp: str = Form(...), password: str = Form(...)):
    user_collection = get_user_collection()
    user = await user_collection.find_one({"email": email})

    error_context = {"request": request, "email": email}
    if not user:
        return templates.TemplateResponse("verify.html", {**error_context, "error": "User not found. Please start over."})
    if user.get("is_verified"):
        return templates.TemplateResponse("verify.html", {**error_context, "error": "This account is already verified."})
    if datetime.datetime.utcnow() > user.get("otp_expires_at"):
        return templates.TemplateResponse("verify.html", {**error_context, "error": "OTP has expired. Please request a new one."})
    if not verify_password(otp, user.get("otp_hash")):
        return templates.TemplateResponse("verify.html", {**error_context, "error": "Invalid OTP."})

    hashed_password = get_password_hash(password)
    verified_user_count = await user_collection.count_documents({"is_verified": True})
    is_admin = verified_user_count == 0

    await user_collection.update_one(
        {"email": email},
        {
            "$set": {"password": hashed_password, "is_admin": is_admin, "is_verified": True},
            "$unset": {"otp_hash": "", "otp_expires_at": ""}
        }
    )

    return RedirectResponse(url="/?message=Registration successful! You can now log in.", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/token")
async def login_for_access_token(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = await get_user_collection().find_one({"email": form_data.username})
    if not user or not user.get("is_verified") or not verify_password(form_data.password, user.get("password")):
        return RedirectResponse(url="/?error=Incorrect email or password", status_code=status.HTTP_303_SEE_OTHER)
    
    access_token = create_access_token(data={"sub": user["email"]})
    
    redirect_url = "/admin" if user.get("is_admin") else "/dashboard"
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(key="access_token", value=access_token, httponly=True, samesite="lax")
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie(key="access_token")
    return response

@app.post("/upload")
async def upload_screenshot(request: Request, user: dict = Depends(get_current_user_required), file: UploadFile = File(...)):
    try:
        image_bytes = await file.read()
        extracted_data = await analyze_screenshot_with_groq(image_bytes)
        
        user_email = user["email"]
        
        existing_entry = await get_screentime_collection().find_one({
            "user_email": user_email,
            "date": extracted_data['date']
        })
        if existing_entry:
            return RedirectResponse(url="/dashboard?error=Data for this date has already been uploaded.", status_code=status.HTTP_303_SEE_OTHER)

        extracted_data["user_email"] = user_email
        extracted_data["uploaded_at"] = datetime.datetime.utcnow()
        await get_screentime_collection().insert_one(extracted_data)
        
        return RedirectResponse(url="/dashboard?message=Screenshot processed and data saved successfully!", status_code=status.HTTP_303_SEE_OTHER)

    except ValueError as e:
        return RedirectResponse(url=f"/dashboard?error={str(e)}", status_code=status.HTTP_303_SEE_OTHER)
    except Exception as e:
        return RedirectResponse(url=f"/dashboard?error=An unexpected error occurred: {str(e)}", status_code=status.HTTP_303_SEE_OTHER)

# Health check endpoint for deployment
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    # The key change is adding host="0.0.0.0"
    uvicorn.run(
        "app:app", 
        host="0.0.0.0", 
        port=int(os.environ.get("PORT", 8000)), 
        reload=True
    )
