from src.web_interface import app
import os
from dotenv import load_dotenv

if __name__ == "__main__":
    load_dotenv()
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True) 