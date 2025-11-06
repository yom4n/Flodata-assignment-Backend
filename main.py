from fastapi import FastAPI, status, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

import database
from auth import auth_router
from students import router as students_router

# Create FastAPI app
app = FastAPI(
    title="Student Management System API",
    description="API for managing student records and user authentication",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5174"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(students_router)  # Uses the prefix defined in the router

# Event handlers
@app.on_event("startup")
async def startup_db_client():
    """Initialize database client and create default admin user on startup."""
    try:
        await database.create_default_admin_user()
        print("✅ Database connection established")
    except Exception as e:
        print(f"❌ Failed to connect to the database: {e}")
        raise

# Root endpoint
@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    """Root endpoint to check if the API is running."""
    return {
        "status": "API is running",
        "docs": "/docs",
        "redoc": "/redoc"
    }

# Health check endpoint
@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
