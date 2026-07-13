def detect_language_from_filename(filename):
    filename = filename.lower()

    if filename.endswith(".py"):
        return "python"

    if filename.endswith(".java"):
        return "java"

    return "unknown"


def detect_language_from_code(code):
    java_keywords = [
        "public class",
        "public static void main",
        "System.out.println",
        "import java",
    ]

    python_keywords = [
        "def ",
        "print(",
        "import ",
        "from ",
        "if ",
    ]

    for keyword in java_keywords:
        if keyword in code:
            return "java"

    for keyword in python_keywords:
        if keyword in code:
            return "python"

    return "unknown"