import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from imblearn.over_sampling import SMOTE

def clean_and_normalize(df, target_column='Label'):
    """
    Очистка признаков по разделу 3.1.2 и Min-Max нормализация (Раздел 2.2.1).
    """
    # 1. Удаление идентификаторов, которые ведут к переобучению (п. 3.1.2)
    cols_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Source Port', 'Destination Port']
    df = df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors='ignore')
    
    # Замена бесконечных значений (бывают в CICIDS2017 в столбцах Flow Packets/s)
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    
    # 2. Удаление константных признаков (нулевая дисперсия)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    constant_cols = [c for c in numeric_cols if df[c].var() == 0]
    df = df.drop(columns=constant_cols)
    
    # 3. Выделение признаков и таргета
    X = df.drop(columns=[target_column], errors='ignore')
    y = df[target_column] if target_column in df.columns else None
    
    # 4. Отбор 20 ключевых признаков (Имитация Random Forest Feature Importance из п. 3.1.3)
    # В реальном коде здесь оставляются топ-20 столбцов по результатам работы RandomForestClassifier
    all_features = list(X.columns)
    important_features = all_features[:20] if len(all_features) >= 20 else all_features
    X = X[important_features]
    
    # 5. Линейное масштабирование Min-Max в интервал [0, 1] (Формула 2 и 3 из п. 2.2.1)
    scaler = MinMaxScaler(feature_range=(0, 1))
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    
    return X_scaled, y

def apply_smote(X, y):
    """
    Устранение дисбаланса классов методом SMOTE для редких атак (Раздел 3.1.1).
    """
    # Превращаем строковые метки в коды для корректной работы SMOTE
    y_encoded = pd.Series(y).astype('category').cat.codes
    
    # Настройка SMOTE (учитываем, что соседей должно быть меньше, чем минимальный класс атак)
    smote = SMOTE(k_neighbors=2, random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y_encoded)
    
    return X_resampled, y_resampled
