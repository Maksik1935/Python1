
# Входное слово
word = input("Введите слово: ")

length = len(word)

# Проверяем чётность длины
if length % 2 == 0:
    # Чётное — выводим две средние буквы
    middle_left = length // 2 - 1
    middle_right = length // 2 + 1
    result = word[middle_left:middle_right]
else:
    # Нечётное — выводим одну среднюю букву
    middle = length // 2
    result = word[middle]

print("Результат:", result)