import numpy as np

class ResponseController:
    def __init__(self, high_threshold=0.8, medium_threshold=0.5):
        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold

    def evaluate_prediction(self, prediction_vector, classes):
        """
        prediction_vector: выход слоя Softmax (массив вероятностей)
        classes: список классов (например, ['BENIGN', 'DoS', 'BruteForce', 'Probe', 'WebAttack'])
        """
        max_idx = np.argmax(prediction_vector)
        prob = prediction_vector[max_idx]
        predicted_class = classes[max_idx]
        
        if predicted_class == 'BENIGN':
            return {"status": "Passive", "action": "Log", "risk": "Low"}
            
        # Если обнаружена атака, смотрим на пороговую фильтрацию
        if prob >= self.high_threshold:
            return {
                "status": "Preventive", 
                "action": f"execute_active_response (Block IP/Reset TCP for {predicted_class})", 
                "risk": "Critical",
                "confidence": prob
            }
        elif self.medium_threshold <= prob < self.high_threshold:
            return {
                "status": "Reactive", 
                "action": f"redirect_to_honeypot / Alert SOC analyst for {predicted_class}", 
                "risk": "Medium",
                "confidence": prob
            }
        else:
            return {"status": "Passive", "action": "Log to SIEM", "risk": "Low", "confidence": prob}
