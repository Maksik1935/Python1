import pandas1 as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ===== ЭТАП 2. Загрузка и анализ данных =====

file_path = '../events.json'

# Если JSON — это массив объектов:  [ {..}, {..}, ... ]
df = pd.read_json(file_path)

# Посмотрим на первые строки
print("Первые строки датафрейма:")
print(df.head())

# Проверим, есть ли поле 'signature'
if 'signature' not in df.columns:
    raise ValueError("В данных нет поля 'signature'")

# Посчитаем распределение по типам событий (поле 'signature')
sig_counts = df['signature'].value_counts()          # Series: signature -> count
print("\nРаспределение событий по типам (signature):")
print(sig_counts)

# Для удобства можно превратить в отдельный датафрейм
sig_counts_df = sig_counts.reset_index()
sig_counts_df.columns = ['signature', 'count']

print("\nТаблица распределения:")
print(sig_counts_df)

# ===== ЭТАП 3. Визуализация данных =====

sns.set(style="whitegrid")

plt.figure(figsize=(12, 6))
# Строим горизонтальную столбчатую диаграмму
sns.barplot(
    data=sig_counts_df,
    x='count',
    y='signature'
)

plt.title('Распределение типов событий информационной безопасности по полю "signature"')
plt.xlabel('Количество событий')
plt.ylabel('Тип события (signature)')
plt.tight_layout()
plt.show()
