
import requests
import json

url = "https://jsonplaceholder.typicode.com/posts"

response = requests.get(url)

# Заголовки ответа
print("=== HEADERS ===")
for key, value in response.headers.items():
    print(f"{key}: {value}")

# Тело ответа (как текст)
data = response.json()
first_five = data[:5]
print(json.dumps(first_five, indent=2, ensure_ascii=False))
