# 📱 Digital Wellness Monitor

A full-stack FastAPI application designed to help educational institutions monitor and analyze student smartphone usage habits. The system leverages **AI (Groq/Llama)** to automatically extract data from screen time screenshots, visualize usage trends, and flag high-risk digital dependency behaviors via an administrative dashboard.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.95%2B-009688)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-green)
![AI](https://img.shields.io/badge/AI-Groq%20Cloud-orange)
![License](https://img.shields.io/badge/License-MIT-purple)

---

## ✨ Key Features

### 🤖 AI-Powered Analysis
* **Groq API Integration:** Uses Llama models to analyze uploaded screenshots with high speed.
* **Layout Validation:** Detects and validates "Digital Wellbeing" (Android) and "Screen Time" (iOS) interface layouts.
* **Data Extraction:** Automatically extracts Date, Total Screen Time, and Top 3 Apps used.

### 🔐 Secure Authentication
* **Institutional Verification:** Registration is restricted strictly to `@iiitn.ac.in` email domains.
* **OTP Verification:** Email-based One-Time Password system powered by `fastapi-mail`.
* **Session Management:** Uses secure JWT (JSON Web Tokens) stored in HTTP-only cookies.

### 📊 Student Dashboard
* **Calendar Integration:** View screen time history by Month, Week, or Day.
* **Data Visualization:** Interactive breakdown of usage duration and top applications.
* **Smart Upload:** Drag-and-drop screenshot uploading with immediate AI feedback.

### 👨‍💼 Admin Portal
* **Student Directory:** Searchable list of all registered students (search by Email or Roll Number).
* **Attention Flags:** Automatically highlights students who:
    * Have **High Screentime** (> 8 hours/day).
    * Have **No Submissions** in the last 7 days.
* **Analytics:** View weekly averages and percentage changes in usage over time.

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python, FastAPI |
| **Database** | MongoDB (Async Motor driver) |
| **AI Engine** | Groq Cloud API |
| **Frontend** | HTML5, CSS3, Jinja2 Templates |
| **Auth** | OAuth2 with Password hashing (Bcrypt) |

---

## 🚀 Installation & Setup

### 1. Prerequisites
* Python 3.9+
* MongoDB (Running locally or via Atlas)
* Groq API Key

### 2. Clone the Repository
```bash
git clone [https://github.com/yourusername/digital-wellness-monitor.git](https://github.com/yourusername/digital-wellness-monitor.git)
cd digital-wellness-monitor
3. Virtual EnvironmentWindows:Bashpython -m venv venv
venv\Scripts\activate
macOS/Linux:Bashpython3 -m venv venv
source venv/bin/activate
4. Install DependenciesYou can install the required packages directly using pip:Bashpip install fastapi uvicorn pydantic pydantic-settings email-validator motor groq fastapi-mail python-jose[cryptography] passlib[bcrypt] python-multipart jinja2 aiofiles requests
5. Configuration (.env)Create a .env file in the root directory and configure your credentials:Ini, TOML# App Security
SECRET_KEY=change_this_to_a_secure_random_string
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
MONGO_DETAILS=mongodb://localhost:27017

# AI Service
GROQ_API_KEY=your_groq_api_key_here

# Email Service (Gmail Example)
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_FROM=your-email@gmail.com
MAIL_PORT=587
MAIL_SERVER=smtp.gmail.com
MAIL_STARTTLS=True
MAIL_SSL_TLS=False
6. Run the ApplicationBashuvicorn app:app --reload
The server will start at http://localhost:8000.📖 Usage GuideRegistration FlowGo to the home page (/).Enter an institutional email (...iiitn.ac.in).Check your email for the OTP code.Complete setup with the OTP and a password.Note: The first user registered in the system is automatically assigned Admin privileges.Student WorkflowLog in to the dashboard.Take a screenshot of your phone's screen time summary.Click "Upload Screenshot".The AI analyzes the image and populates the calendar.Admin WorkflowLog in (account must have Admin privileges).Navigate to /admin.Use the search bar to find students.Click on a student's card to view their detailed weekly analysis.🔌 API EndpointsMethodEndpointDescriptionPOST/initiate-registrationSend OTP to emailPOST/complete-registrationVerify OTP and create userPOST/tokenLogin (Returns JWT)GET/api/screentimeGet raw JSON usage dataPOST/uploadUpload screenshot (JSON or Form)GET/admin/student/{email}Get specific student analytics🤝 ContributingContributions are welcome! Please fork the repository and submit a pull request for any features or bug fixes.📄 LicenseThis project is open-source and available under the MIT License.
