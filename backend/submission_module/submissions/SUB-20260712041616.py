def calculate_average(numbers):
    total = sum(numbers)
    average = total / len(numbers)
    return average


marks = []

for i in range(5):
    mark = int(input(f"Enter mark {i + 1}: "))
    marks.append(mark)

avg = calculate_average(marks)

print("\nMarks:", marks)
print("Average:", avg)

if avg >= 75:
    print("Result: Passed with Distinction")
elif avg >= 40:
    print("Result: Passed")
else:
    print("Result: Failed")