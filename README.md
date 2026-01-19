# 📱 Digital Wellness Monitor

A full-stack **FastAPI** application designed to help educational institutions monitor and analyze student smartphone usage habits. The system leverages **AI (Groq + LLaMA)** to automatically extract data from screen time screenshots, visualize usage trends, and flag high-risk digital dependency behaviors via an administrative dashboard.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.95%2B-009688)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-green)
![AI](https://img.shields.io/badge/AI-Groq%20Cloud-orange)
![License](https://img.shields.io/badge/License-MIT-purple)

---

## ✨ Key Features

### 🤖 AI-Powered Analysis
- **Groq API Integration:** Uses LLaMA models for ultra-fast screenshot analysis.
- **Layout Validation:** Detects and validates:
  - Android **Digital Wellbeing**
  - iOS **Screen Time**
- **Data Extraction:** Automatically extracts:
  - Date
  - Total Screen Time
  - Top 3 Apps Used

---

### 🔐 Secure Authentication
- **Institutional Verification:** Registration restricted to `@iiitn.ac.in` email domains.
- **OTP Verification:** Email-based OTP using `fastapi-mail`.
- **Session Management:** Secure JWT authentication stored in **HTTP-only cookies**.

---

### 📊 Student Dashboard
- **Calendar View:** Monthly, weekly, and daily screen time history.
- **Usage Visualization:** App-wise usage breakdown.
- **Smart Upload:** Drag-and-drop screenshot uploads with instant AI feedback.

---

### 👨‍💼 Admin Portal
- **Student Directory:** Search by email or roll number.
- **Attention Flags:** Automatically highlights students with:
  - ⚠️ **High Screen Time** (> 8 hours/day)
  - ❌ **No Submissions** in last 7 days
- **Analytics:** Weekly averages and percentage change tracking.

---

## 🛠️ Tech Stack

| Component | Technology |
|--------|------------|
| Backend | Python, FastAPI |
| Database | MongoDB (Async Motor) |
| AI Engine | Groq Cloud (LLaMA Models) |
| Frontend | HTML5, CSS3, Jinja2 |
| Auth | JWT, OAuth2, Bcrypt |

---

## 🚀 Installation & Setup

### 1️⃣ Prerequisites
- Python **3.9+**
- MongoDB (Local or Atlas)
- Groq API Key

---

### 2️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/digital-wellness-monitor.git
cd digital-wellness-monitor
