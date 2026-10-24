import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run("backend.app:create_app", factory=True, host="127.0.0.1", port=int(os.getenv("PORT", "8110")), workers=1, access_log=False)
