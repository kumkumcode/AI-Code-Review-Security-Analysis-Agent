from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware  # Added for frontend-backend communication
from pydantic import BaseModel

from submission_module.detector import detect_language_from_code
from submission_module.validator import validate_code
from submission_module.storage import save_submission


app = FastAPI()

# ---- Infosys Enterprise CORS Configuration ----
# This allows your local HTML/JS frontend to securely communicate with the FastAPI gateway
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits requests from local file system or live server origins
    allow_credentials=True,
    allow_methods=["*"],  # Permits GET, POST, and options protocols
    allow_headers=["*"],  # Permits all standard enterprise headers
)
# -----------------------------------------------


class PasteCodeRequest(BaseModel):
    code: str


@app.get("/")
def home():
    return {
        "message": "AI Code Review Submission Module is running"
    }


@app.post("/submit/paste")
def submit_pasted_code(request: PasteCodeRequest):
    code = request.code

    language = detect_language_from_code(code)

    if language == "unknown":
        return {
            "status": "failed",
            "message": "Could not detect language. Only Python and Java are supported."
        }

    is_valid, validation_message = validate_code(code, language)

    if not is_valid:
        return {
            "status": "failed",
            "detected_language": language,
            "message": validation_message
        }

    metadata = save_submission(code, language, "paste")

    return {
        "status": "success",
        "message": "Code submitted successfully",
        "submission": metadata
    }


@app.post("/submit/upload")
async def submit_uploaded_file(file: UploadFile = File(...)):
    # 1. Get the filename of the uploaded file
    filename = file.filename

    # 2. Check the file extension to find the language
    if filename.endswith(".py"):
        language = "python"
    elif filename.endswith(".java"):
        language = "java"
    else:
        return {
            "status": "failed",
            "message": "Only .py and .java files are allowed."
        }

    # 3. Read the text content inside the file
    file_bytes = await file.read()
    code = file_bytes.decode("utf-8")

    # 4. Validate the code syntax using your validation module
    is_valid, validation_message = validate_code(code, language)

    if not is_valid:
        return {
            "status": "failed",
            "detected_language": language,
            "message": validation_message
        }

    # 5. Save the file using your existing storage module
    metadata = save_submission(code, language, "upload")

    # 6. Return standard success response matching your milestone goals
    return {
        "status": "success",
        "message": "File uploaded and validated successfully",
        "submission": metadata
    }