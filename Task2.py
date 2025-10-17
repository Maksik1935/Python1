boys = ['Peter', 'Alex', 'John', 'Arthur', 'Richard']
girls = ['Kate', 'Liza', 'Kira', 'Emma', 'Trisha']

# Проверяем, у всех ли хватит пары
if len(boys) != len(girls):
    print("Внимание, кто-то может остаться без пары!")
else:
    # Сортируем имена по алфавиту без учёта регистра
    boys_sorted = sorted(boys, key=str.lower)
    girls_sorted = sorted(girls, key=str.lower)

    print("Идеальные пары:")
    for b, g in zip(boys_sorted, girls_sorted):
        print(f"{b} и {g}")