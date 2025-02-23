import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_config=None,  # Use our own logging configuration
        proxy_headers=True,
        forwarded_allow_ips="*"
    ) 