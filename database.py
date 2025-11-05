from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from .config import DATABASE_URL, DATABASE_NAME

# Initialize password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database connection
client = AsyncIOMotorClient(DATABASE_URL)
db = client[DATABASE_NAME]

# Collections
user_collection = db["users"]
student_collection = db["students"]

async def create_default_admin_user():
 
    admin_user = {
        "username": "admin",
        "full_name": "Administrator",
        "email": "admin@example.com",
        "hashed_password": pwd_context.hash("adminpassword"),
        "role": "admin",
        "disabled": False
    }
    
    # Check if admin user already exists
    existing_user = await user_collection.find_one({"username": "admin"})
    
    if not existing_user:
        # Insert the admin user if it doesn't exist
        result = await user_collection.insert_one(admin_user)
        if result.inserted_id:
            print("Default admin user created successfully")
        else:
            print("Failed to create default admin user")
