import requests

API_KEY = "ВСТАВЬ_СВОЙ_API_КЛЮЧ_ТУТ"
BASE_URL = "https://api.openweathermap.org/data/2.5/weather"


def get_weather(city_name: str):
    params = {
        "q": city_name,       # город
        "appid": API_KEY,     # ваш API-ключ
        "units": "metric",    # градусы Цельсия
        "lang": "ru",         # описание погоды по-русски
    }

    response = requests.get(BASE_URL, params=params)
    response.raise_for_status()  # выбросит исключение, если код ответа != 200

    data = response.json()
    temp = data["main"]["temp"]
    description = data["weather"][0]["description"]

    return temp, description


def main():
    city = input("Введите название города: ")

    try:
        temp, description = get_weather(city)
        print(f"Сейчас в городе {city}: {temp:.1f}°C, {description}.")
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print("Город не найден. Проверьте написание.")
        else:
            print("Произошла ошибка при запросе к API:", e)
    except requests.exceptions.RequestException as e:
        print("Ошибка сети:", e)


if __name__ == "__main__":
    main()