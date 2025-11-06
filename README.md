# Student Record Management System - FastAPI Backend

This document guides you through setting up and running the FastAPI backend for the Student Record Management System.

## 1. Project Setup

### 1.1 Clone the Repository
Clone the project repository to your local machine:
```bash
git clone https://github.com/yom4n/Flodata-assignment-Backend
```

### 1.2 Virtual Environment
It is highly recommended to use a virtual environment to manage dependencies.

In the root directory: 
```bash
# Create the virtual environment
python -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows (Command Prompt):
# .\venv\Scripts\activate
```

### 1.3 Install Dependencies
Install all necessary Python packages using the requirements.txt file:
```bash
pip install -r requirements.txt
```

## 2. Database Configuration (MongoDB Atlas)
This project uses MongoDB for persistent storage, accessed via a connection string.

### 2.1 Get Your MongoDB Atlas Connection String
1. Sign up for or log into [MongoDB Atlas](https://www.mongodb.com/cloud/atlas/register)
2. Create or select your cluster
3. Click "Connect" on your cluster dashboard
4. Choose "Connect your application"
5. Select Python as the driver
6. Copy the connection string (it will look like `mongodb+srv://<username>:<password>@cluster0.xxxxx.mongodb.net/`)

## 3. Environment Variables
The application relies on environment variables for security and configuration.

### 3.1 Create the .env File
Create a new file named `.env` in the root directory. Copy the contents of `.env.example` into your new `.env` file:

```bash
# Create the .env file
cp .env.example .env
```

### 3.2 Configure .env Variables
Ensure the following variables are correctly set in your `.env` file:

```
DATABASE_URL=your_mongodb_atlas_connection_string
SECRET_KEY=your-secure-secret-key-here
DATABASE_NAME=student_db
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

- **DATABASE_URL**: The full connection string obtained from MongoDB Atlas (section 2.1). Replace `<username>` and `<password>` with your actual database credentials.
- **SECRET_KEY**: A secure, random string for JWT token signing (generate with `openssl rand -hex 32`)
- **DATABASE_NAME**: The name of your MongoDB database (default: student_db)
- **ALGORITHM**: Keep as HS256 for JWT hashing
- **ACCESS_TOKEN_EXPIRE_MINUTES**: Token expiration time in minutes (default: 30)

## 4. Running the Application

Start the FastAPI development server:

```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

## 5. API Documentation

Once the server is running, you can access:
- Interactive API documentation: `http://localhost:8000/docs`
- Alternative documentation: `http://localhost:8000/redoc`
