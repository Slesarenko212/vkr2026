import sys
import os
import time
import numpy as np
import tensorflow as tf

# Добавляем корень проекта в путь для импорта модулей
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.model import build_hybrid_model
from src.controller import ResponseController

def run_load_test(num_samples=5000, window_size=10, num_features=20):
    print("--- Инициализация нагрузочного тестирования ---")
    
    # 1. Инициализация компонентов системы
    model = build_hybrid_model(window_size, num_features)
    controller = ResponseController()
    classes = ['BENIGN', 'DoS', 'BruteForce', 'Probe', 'WebAttack']
    
    # 2. Генерируем синтетический тензор входящей телеметрии (размерность M, T, F)
    # Имитируем нормализованные признаки в диапазоне [0, 1]
    mock_traffic = np.random.rand(num_samples, window_size, num_features).astype(np.float32)
    
    print(f"Подготовлено тестовых пакетов/событий: {num_samples}")
    print("Запуск потоковой классификации (Эмуляция Online режима)...")
    
    # Прогрев модели (Warm-up для точного замера времени)
    _ = model.predict(mock_traffic[:1], verbose=0)
    
    start_time = time.time()
    
    # 3. Имитация последовательной обработки пакетов
    # Для оптимизации в реальном IDS пакеты объединяются в мини-батчи
    batch_size = 100 
    predictions = []
    
    for i in range(0, num_samples, batch_size):
        chunk = mock_traffic[i:i+batch_size]
        # Измерение задержки инференса
        chunk_preds = model.predict(chunk, verbose=0)
        predictions.extend(chunk_preds)
        
    end_time = time.time()
    total_time = end_time - start_time
    
    # 4. Логическая обработка результатов контроллером
    for pred in predictions[:5]: # Выведем первые 5 вердиктов для примера
        verdict = controller.evaluate_prediction(pred, classes)
        # Имитируем отправку в логи/SOAR
        pass

    # 5. Расчет целевых метрик эффективности
    eps = num_samples / total_time
    avg_latency_ms = (total_time / num_samples) * 1000
    
    print("\n--- Результаты нагрузочного тестирования ---")
    print(f"Общее время обработки: {total_time:.4f} сек.")
    print(f"Производительность (EPS): {eps:.2f} событий/сек. (Целевое значение по ТЗ: >= 500)")
    print(f"Средняя задержка на один пакет (Latency): {avg_latency_ms:.4f} мс.")
    
    if eps >= 500:
        print("[УСПЕШНО] Система удовлетворяет требованиям производительности.")
    else:
        print("[ВНИМАНИЕ] Требуется оптимизация (квантование модели или TensorRT).")

if __name__ == "__main__":
    run_load_test()
