from submission_module.detector import detect_language_from_code
from submission_module.validator import validate_code
from submission_module.storage import save_submission


code = '''
public class Main {
    public static void main(String[] args) {
        System.out.println("Hello from Java");
    }
'''

language = detect_language_from_code(code)

is_valid, message = validate_code(code, language)

if is_valid:
    metadata = save_submission(code, language, "paste")
    print("Submission saved successfully")
    print("Submission ID:", metadata["submission_id"])
    print("Detected language:", metadata["language"])
else:
    print("Submission failed")
    print(message)