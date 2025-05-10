#!/bin/bash

# Создание виртуального окружения
python3 -m venv venv

# Активация виртуального окружения
source ./venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt

# Проверка и создание директории tmp
if [ ! -d "tmp" ]; then
  mkdir tmp
fi

python src/main.py
