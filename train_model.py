import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from app.model import ATTACK_CATEGORY_MAP

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, names=COLUMN_NAMES)
    df["label"] = df["label"].str.replace(".", "", regex=False)
    return df

FEATURE_ORDER = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "count", "srv_count", "serror_rate", "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count",
]
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]


def main():
    train_df = load_dataset("data/KDDTrain+.txt")
    test_df = load_dataset("data/KDDTest+.txt")

    # Fit one LabelEncoder per text column on the training data only
    encoders = {}
    for col in CATEGORICAL_COLS:
        le = LabelEncoder()
        train_df[col] = le.fit_transform(train_df[col])
        encoders[col] = le

    X_train = train_df[FEATURE_ORDER]
    y_train = train_df["label"]

    clf = RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1, random_state=42)
    clf.fit(X_train, y_train)

    # Apply the SAME encoders to the test data (never refit on test data)
    for col in CATEGORICAL_COLS:
        le = encoders[col]
        test_df[col] = test_df[col].map(lambda v: v if v in le.classes_ else le.classes_[0])
        test_df[col] = le.transform(test_df[col])

    X_test = test_df[FEATURE_ORDER]
    y_test = test_df["label"]
    preds = clf.predict(X_test)
    print(classification_report(y_test, preds, zero_division=0))
    
    y_test_coarse = y_test.map(ATTACK_CATEGORY_MAP).fillna("unknown")
    preds_coarse = pd.Series(preds, index=y_test.index).map(ATTACK_CATEGORY_MAP).fillna("unknown")
    print(classification_report(y_test_coarse, preds_coarse, zero_division=0))
    print(classification_report(y_test_coarse != "normal", preds_coarse != "normal",
                                target_names=["normal", "malicious"], zero_division=0))
    

    os.makedirs("artifacts", exist_ok=True)
    joblib.dump(clf, "artifacts/model.joblib")
    joblib.dump(encoders, "artifacts/encoders.joblib")
    print("Saved artifacts/model.joblib and artifacts/encoders.joblib")


if __name__ == "__main__":
    main()