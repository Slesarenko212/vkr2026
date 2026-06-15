import numpy as np
import pandas as pd
from tensorflow.keras.utils import to_categorical

def create_sliding_windows(X_data, y_data, window_size=10, stride=1):
    """
    Формирование трехмерных тензоров размерности (Количество_образцов, Временные_шаги, Количество_признаков)
    Согласно разделу 2.3.4.
    """
    X_array = X_data.to_numpy() if isinstance(X_data, pd.DataFrame) else np.array(X_data)
    y_array = y_data.to_numpy() if isinstance(y_data, pd.Series) else np.array(y_data)
    
    X_windows = []
    y_windows = []
    
    # Скользящее окно по строкам
    for i in range(0, len(X_array) - window_size + 1, stride):
        # Окно признаков от t-9 до t (размер window_size)
        X_windows.append(X_array[i : i + window_size])
        
        # Метка класса берется по текущему (последнему) шагу окна t
        y_windows.append(y_array[i + window_size - 1])
        
    X_tensor = np.array(X_windows) # Размерность: (M, T, F)
    y_tensor = np.array(y_windows)
    
    # Перевод меток в One-Hot Encoding для Categorical Cross-Entropy (Раздел 2.2.6)
    num_classes = len(np.unique(y_tensor))
    y_tensor_onehot = to_categorical(y_tensor, num_classes=num_classes)
    
    return X_tensor, y_tensor_onehot

if __name__ == "__main__":
    # Быстрый тест пайплайна на случайных данных
    mock_X = pd.DataFrame(np.random.rand(100, 20))
    mock_y = pd.Series(np.random.randint(0, 5, size=100))
    
    X_t, y_t = create_sliding_windows(mock_X, mock_y, window_size=10)
    print(f"Размерность входного тензора для CNN-LSTM: {X_t.shape}") # Ожидается (91, 10, 20)
    print(f"Размерность тензора ответов (One-Hot): {y_t.shape}")
