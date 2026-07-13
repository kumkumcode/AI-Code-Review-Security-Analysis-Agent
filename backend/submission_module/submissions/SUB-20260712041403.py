import matplotlib.pyplot as plt

# Sample data
years = ['2020', '2021', '2022', '2023']
sales = [25000, 40000, 30000, 45000]

# Create the bar graph
plt.bar(years, sales, color='skyblue')

# Add title and labels
plt.title('Yearly Sales')
plt.xlabel('Year')
plt.ylabel('Sales (in ₹)')

# Show the graph
plt.tight_layout()
plt.show()
