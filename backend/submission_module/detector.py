def detect_language_from_filename(filename: str) -> str:
    filename = filename.lower()
    if filename.endswith(".py"):
        return "python"
    if filename.endswith(".java"):
        return "java"
    return "unknown"


def detect_language_from_code(code: str) -> str:
    if not code or not code.strip():
        return "unknown"

    code_lower = code.lower()

    # Check for Java keywords
    java_keywords = ["public class", "system.out", "public static void main", "import java"]
    if any(keyword in code_lower for keyword in java_keywords):
        return "java"

    # Default to Python for any other code
    return "python"