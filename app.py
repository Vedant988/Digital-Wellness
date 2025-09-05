import os
import datetime
import base64
import json
import re
import random
from typing import Dict, List, Optional
import calendar

# --- Pydantic for Settings Management ---
from pydantic_settings import BaseSettings
from pydantic import EmailStr

# --- FastAPI Imports ---
from fastapi import (
    FastAPI, Request, Form, Depends, HTTPException, status, UploadFile, File, Query
)
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
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
# 5.5. CALENDAR UTILITY FUNCTIONS
# =============================================================================
def get_month_calendar(year: int, month: int):
    """Generate calendar data for a specific month"""
    cal = calendar.monthcalendar(year, month)
    month_name = calendar.month_name[month]
    
    # Flatten the calendar and add date info
    calendar_days = []
    for week in cal:
        for day in week:
            if day == 0:
                calendar_days.append(None)  # Empty cell
            else:
                date_obj = datetime.date(year, month, day)
                calendar_days.append({
                    'day': day,
                    'date': date_obj.strftime("%Y-%m-%d"),
                    'is_today': date_obj == datetime.date.today()
                })
    
    return {
        'year': year,
        'month': month,
        'month_name': month_name,
        'days': calendar_days,
        'weeks': len(cal)
    }

def get_week_calendar(year: int, month: int, day: int):
    """Generate calendar data for a specific week"""
    target_date = datetime.date(year, month, day)
    # Find the Monday of the week containing the target date
    week_start = target_date - datetime.timedelta(days=target_date.weekday())
    
    week_days = []
    for i in range(7):
        date_obj = week_start + datetime.timedelta(days=i)
        week_days.append({
            'day': date_obj.day,
            'date': date_obj.strftime("%Y-%m-%d"),
            'day_name': date_obj.strftime("%a"),
            'is_today': date_obj == datetime.date.today()
        })
    
    return {
        'week_start': week_start.strftime("%Y-%m-%d"),
        'week_end': (week_start + datetime.timedelta(days=6)).strftime("%Y-%m-%d"),
        'days': week_days
    }

async def get_calendar_events(user_email: str, start_date: str, end_date: str):
    """Get screen time events for a date range"""
    cursor = get_screentime_collection().find({
        "user_email": user_email,
        "date": {"$gte": start_date, "$lte": end_date}
    })
    events = await cursor.to_list(length=None)
    
    # Create a map for quick lookup
    events_map = {}
    for event in events:
        events_map[event["date"]] = {
            "totalScreenTime": event.get("totalScreenTime", "0m"),
            "topApps": event.get("topApps", [])
        }
    
    return events_map

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
async def view_dashboard(
    request: Request, 
    user: dict = Depends(get_current_user_required), 
    message: Optional[str] = Query(None), 
    error: Optional[str] = Query(None),
    view: str = Query("month"),  # month, week, day
    year: Optional[int] = Query(None),
    month: Optional[int] = Query(None),
    day: Optional[int] = Query(None)
):
    # Default to current date
    today = datetime.date.today()
    year = year or today.year
    month = month or today.month
    day = day or today.day
    
    # Validate date parameters
    try:
        current_date = datetime.date(year, month, day)
    except ValueError:
        current_date = today
        year, month, day = today.year, today.month, today.day
    
    calendar_data = None
    events_map = {}
    
    if view == "month":
        calendar_data = get_month_calendar(year, month)
        # Get events for the entire month
        month_start = datetime.date(year, month, 1)
        next_month = month + 1 if month < 12 else 1
        next_year = year if month < 12 else year + 1
        try:
            month_end = datetime.date(next_year, next_month, 1) - datetime.timedelta(days=1)
        except ValueError:
            month_end = datetime.date(year, month, 28)  # Fallback
        
        events_map = await get_calendar_events(
            user["email"], 
            month_start.strftime("%Y-%m-%d"), 
            month_end.strftime("%Y-%m-%d")
        )
        
    elif view == "week":
        calendar_data = get_week_calendar(year, month, day)
        events_map = await get_calendar_events(
            user["email"],
            calendar_data["week_start"],
            calendar_data["week_end"]
        )
        
    elif view == "day":
        # For day view, just get the single day's data
        date_str = current_date.strftime("%Y-%m-%d")
        day_events = await get_calendar_events(user["email"], date_str, date_str)
        calendar_data = {
            'current_date': date_str,
            'day_name': current_date.strftime("%A"),
            'event': day_events.get(date_str)
        }
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request, 
        "user": user, 
        "message": message, 
        "error": error,
        "view": view,
        "year": year,
        "month": month,
        "day": day,
        "calendar_data": calendar_data,
        "events_map": events_map,
        "today": today.strftime("%Y-%m-%d")
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

# Add these API routes to your existing app.py file

@app.get("/api/user")
async def get_current_user_api(user: dict = Depends(get_current_user_required)):
    """API endpoint to get current user data"""
    return {
        "email": user["email"],
        "is_admin": user.get("is_admin", False),
        "created_at": user.get("created_at")
    }

@app.get("/api/screentime")
async def get_user_screentime_data(user: dict = Depends(get_current_user_required)):
    """API endpoint to get user's screen time data"""
    try:
        cursor = get_screentime_collection().find(
            {"user_email": user["email"]}
        ).sort("date", -1)
        
        user_data = await cursor.to_list(length=100)
        
        # Convert ObjectId to string and ensure proper format
        formatted_data = []
        for entry in user_data:
            formatted_entry = {
                "date": entry.get("date"),
                "totalScreenTime": entry.get("totalScreenTime"),
                "topApps": entry.get("topApps", [])
            }
            formatted_data.append(formatted_entry)
            
        return formatted_data
        
    except Exception as e:
        print(f"Error fetching screentime data: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch screen time data")

# =============================================================================
# 7.5. CALENDAR API ROUTES
# =============================================================================
@app.get("/api/calendar/events")
async def get_calendar_events_api(
    user: dict = Depends(get_current_user_required),
    start_date: str = Query(...),
    end_date: str = Query(...)
):
    """API endpoint to get calendar events for a date range"""
    try:
        events_map = await get_calendar_events(user["email"], start_date, end_date)
        return events_map
    except Exception as e:
        print(f"Error fetching calendar events: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch calendar events")

# Update the existing /upload route to handle both form and API responses
@app.post("/upload")
async def upload_screenshot(
    request: Request, 
    user: dict = Depends(get_current_user_required), 
    file: UploadFile = File(...)
):
    try:
        # Validate file
        if not file.content_type or not file.content_type.startswith('image/'):
            error_msg = "Please upload a valid image file"
            # Check if it's an API request (JSON response) or form request (redirect)
            if request.headers.get("accept") == "application/json":
                raise HTTPException(status_code=400, detail=error_msg)
            return RedirectResponse(
                url=f"/dashboard?error={error_msg}", 
                status_code=status.HTTP_303_SEE_OTHER
            )

        # Check file size (10MB limit)
        file_size = 0
        image_bytes = bytearray()
        
        # Read file in chunks to check size
        chunk_size = 1024 * 1024  # 1MB chunks
        while chunk := await file.read(chunk_size):
            file_size += len(chunk)
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                error_msg = "File size must be less than 10MB"
                if request.headers.get("accept") == "application/json":
                    raise HTTPException(status_code=400, detail=error_msg)
                return RedirectResponse(
                    url=f"/dashboard?error={error_msg}", 
                    status_code=status.HTTP_303_SEE_OTHER
                )
            image_bytes.extend(chunk)
        
        # Reset file position
        image_bytes = bytes(image_bytes)
        
        # Process with AI
        extracted_data = await analyze_screenshot_with_groq(image_bytes)
        
        user_email = user["email"]
        
        # Check for existing entry
        existing_entry = await get_screentime_collection().find_one({
            "user_email": user_email,
            "date": extracted_data['date']
        })
        
        if existing_entry:
            error_msg = "Data for this date has already been uploaded."
            if request.headers.get("accept") == "application/json":
                raise HTTPException(status_code=409, detail=error_msg)
            return RedirectResponse(
                url=f"/dashboard?error={error_msg}", 
                status_code=status.HTTP_303_SEE_OTHER
            )

        # Save to database
        extracted_data["user_email"] = user_email
        extracted_data["uploaded_at"] = datetime.datetime.utcnow()
        await get_screentime_collection().insert_one(extracted_data)
        
        success_msg = "Screenshot processed and data saved successfully!"
        
        # Return appropriate response
        if request.headers.get("accept") == "application/json":
            return {
                "message": success_msg,
                "data": {
                    "date": extracted_data["date"],
                    "totalScreenTime": extracted_data["totalScreenTime"],
                    "topApps": extracted_data["topApps"]
                }
            }
        else:
            return RedirectResponse(
                url=f"/dashboard?message={success_msg}", 
                status_code=status.HTTP_303_SEE_OTHER
            )

    except ValueError as e:
        error_msg = str(e)
        if request.headers.get("accept") == "application/json":
            raise HTTPException(status_code=400, detail=error_msg)
        return RedirectResponse(
            url=f"/dashboard?error={error_msg}", 
            status_code=status.HTTP_303_SEE_OTHER
        )
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        print(f"Upload error: {e}")
        error_msg = f"An unexpected error occurred: {str(e)}"
        if request.headers.get("accept") == "application/json":
            raise HTTPException(status_code=500, detail=error_msg)
        return RedirectResponse(
            url=f"/dashboard?error={error_msg}", 
            status_code=status.HTTP_303_SEE_OTHER
        )

# Add error handling middleware for better debugging
@app.exception_handler(400)
async def bad_request_handler(request: Request, exc: HTTPException):
    """Handle 400 errors with detailed logging"""
    print(f"Bad Request - URL: {request.url}, Headers: {dict(request.headers)}")
    print(f"Error: {exc.detail}")
    
    # If it's a multipart form error, redirect to dashboard with error
    if "boundary" in str(exc.detail).lower() or "multipart" in str(exc.detail).lower():
        return RedirectResponse(
            url="/dashboard?error=File upload failed. Please try again with a valid image file.", 
            status_code=status.HTTP_303_SEE_OTHER
        )
    
    # For API requests, return JSON error
    if request.headers.get("accept") == "application/json":
        return JSONResponse(
            status_code=400,
            content={"detail": exc.detail}
        )
    
    # For form requests, redirect with error
    return RedirectResponse(
        url=f"/dashboard?error={exc.detail}", 
        status_code=status.HTTP_303_SEE_OTHER
    )

# Add CORS headers for API requests
@app.middleware("http")
async def add_cors_header(request: Request, call_next):
    response = await call_next(request)
    
    # Add CORS headers for API routes
    if request.url.path.startswith("/api/"):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE"
        response.headers["Access-Control-Allow-Headers"] = "*"
    
    return response

# Health check endpoint for deployment
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    # The key change is adding host="0.0.0.0"
    uvicorn.run(
        "app:app",
        # host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)), 
        reload=True
    )
