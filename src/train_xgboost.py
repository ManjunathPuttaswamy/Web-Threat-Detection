import joblib
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, classification_report
from src.utils import print_header

def train_xgboost(X_train, X_test, y_train, y_test, params, save_path):
    print_header("TRAINING XGBOOST")

    model = XGBClassifier(**params)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)

    print("Accuracy:", accuracy_score(y_test, preds))
    print("Classification Report:\n", classification_report(y_test, preds))

    joblib.dump(model, save_path)
    print(f"XGBoost model saved → {save_path}")