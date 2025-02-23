from fastapi import FastAPI
import uvicorn
from app.api import router as api_router
from app.logger import setup_logging
from fastapi.middleware.cors import CORSMiddleware

# Set up logging
logger = setup_logging()

# Create main application
app = FastAPI(
    title="ArbiterAgent",
    description="An intelligent agent that arbitrates security findings by deduplicating similar issues and evaluating finding quality",
    version="1.0.0",
    root_path="",  # Allow for proxy path handling
    servers=[{"url": "http://0.0.0.0:8080"}]  # Set default server
)

# Add root endpoint
@app.get("/")
@app.head("/")
async def root():
    return {"status": "ok", "message": "ArbiterAgent is running"}

# Add health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

# Include API routes
app.include_router(api_router)

if __name__ == "__main__":
    logger.info("Starting ArbiterAgent...")
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",  # Default host
        port=8080,
        reload=True,
        log_config=None,  # Use our own logging configuration
        proxy_headers=True,  # Enable proxy headers
        forwarded_allow_ips="*"  # Trust forwarded headers from all IPs
    ) 