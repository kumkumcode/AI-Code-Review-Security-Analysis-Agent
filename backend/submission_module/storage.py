import json
import os
from datetime import datetime


SUBMISSION_FOLDER = "submission_module/submissions"


def create_submission_folder():
    if not os.path.exists(SUBMISSION_FOLDER):
        os.makedirs(SUBMISSION_FOLDER)


def generate_submission_id():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"SUB-{timestamp}"


def save_submission(code, language, source_type):
    create_submission_folder()

    submission_id = generate_submission_id()

    if language == "python":
        extension = ".py"
    elif language == "java":
        extension = ".java"
    else:
        extension = ".txt"

    code_filename = f"{submission_id}{extension}"
    metadata_filename = f"{submission_id}.json"

    code_path = os.path.join(SUBMISSION_FOLDER, code_filename)
    metadata_path = os.path.join(SUBMISSION_FOLDER, metadata_filename)

    with open(code_path, "w", encoding="utf-8") as code_file:
        code_file.write(code)

    metadata = {
        "submission_id": submission_id,
        "language": language,
        "source_type": source_type,
        "code_file": code_filename,
        "file_path": code_path,  # Added to resolve NoneType path errors
        "created_at": datetime.now().isoformat()
    }

    with open(metadata_path, "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=4)

    return metadata