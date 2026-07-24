def calculate_factorial(n):
    if n < 0:
        return None
    if n == 0 or n == 1:
        return 1
    
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result

# Test execution
number = 5
print(f"The factorial of {number} is {calculate_factorial(number)}")