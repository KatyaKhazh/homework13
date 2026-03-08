import os
import requests
import json

# ==============================
# НАСТРОЙКИ
# ==============================

# Способ 1 (рекомендуемый): хранить ключ в переменной окружения
# setx VT_API_KEY "ваш_ключ" (Windows)

API_KEY = os.getenv("VT_API_KEY")

#Хэш файла
FILE_HASH = "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"

if not API_KEY:
    raise ValueError("API ключ не найден! Задайте переменную окружения VT_API_KEY.")

url = f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"

headers = {
    "x-apikey": API_KEY
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    print("Результат анализа файла:")
    print(f"malicious: {malicious}")
    print(f"suspicious: {suspicious}")
    print(f"harmless: {harmless}")
    print(f"undetected: {undetected}")

    if malicious > 0:
        print("\nИТОГ: файл malicious")
    elif suspicious > 0:
        print("\nИТОГ: файл suspicious")
    else:
        print("\nИТОГ: явных признаков вредоносности не найдено")
else:
    print(f"Ошибка: {response.status_code}")
    print(response.text)