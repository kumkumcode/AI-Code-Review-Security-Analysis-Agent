import ast


def validate_python_code(code):
    try:
        ast.parse(code)
        return True, "Python syntax is valid"
    except SyntaxError as error:
        return False, f"Python syntax error: {error}"


def validate_java_code(code):
    if "class" not in code:
        return False, "Java code must contain a class"

    if code.count("{") != code.count("}"):
        return False, "Java braces are not balanced"

    if code.strip() == "":
        return False, "Java code cannot be empty"

    return True, "Java basic syntax looks valid"


def validate_code(code, language):
    if language == "python":
        return validate_python_code(code)

    if language == "java":
        return validate_java_code(code)

    return False, "Unsupported or unknown language"