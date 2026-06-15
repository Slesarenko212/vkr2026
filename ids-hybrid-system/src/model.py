import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Flatten, LSTM, Conv1D, MaxPooling1D, TimeDistributed, Input

def build_hybrid_model(window_size=10, num_features=20, num_classes=5):
    """
    Построение гибридной модели CNN-LSTM.
    Размерность входа: (Batch_Size, Window_Size, Num_Features) -> (M, T, F)
    """
    model = Sequential()
    
    # Входной уровень
    model.add(Input(shape=(window_size, num_features)))
    
    # Блок CNN (внутри скользящего окна)
    # Используем Reshape для добавления канала под Conv1D внутри каждого шага
    # Или применяем одномерную свертку напрямую к признакам, если смотрим локальные связи
    model.add(TimeDistributed(Conv1D(filters=32, kernel_size=3, padding='same', activation='relu')))
    model.add(TimeDistributed(MaxPooling1D(pool_size=2, padding='same')))
    model.add(TimeDistributed(Flatten()))
    
    # Блок LSTM (Анализ временных последовательностей высокоуровневых признаков)
    model.add(LSTM(units=64, return_sequences=False))
    model.add(Dropout(0.3)) # Регуляризация против зазубривания IP-адресов
    
    # Выходной блок (Финал классификации)
    model.add(Dense(units=32, activation='relu'))
    model.add(Dense(units=num_classes, activation='softmax')) # Категориальный выход
    
    # Компиляция
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
        loss='categorical_crossentropy',
        metrics=['AUC', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
    )
    
    return model

if __name__ == "__main__":
    # Тестовая сборка для проверки размерностей
    my_model = build_hybrid_model()
    my_model.summary()
