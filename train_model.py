
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
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]

FEATURE_ORDER = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "serror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "dst_host_srv_count",
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

CLASS_LABELS = ["normal", "dos", "probe", "r2l", "u2r"]


def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, names=COLUMN_NAMES)
    df["label"] = df["label"].str.replace(".", "", regex=False)
    return df


def map_attack_labels(labels: pd.Series, dataset_name: str) -> pd.Series:
    mapped = labels.map(ATTACK_CATEGORY_MAP)

    if mapped.isna().any():
        unmapped = sorted(labels[mapped.isna()].unique())
        raise ValueError(
            f"Unmapped labels in {dataset_name}: {unmapped}"
        )

    return mapped


def encode_categorical_features(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
):
    encoders = {}

    for col in CATEGORICAL_COLS:
        encoder = LabelEncoder()

        train_df[col] = encoder.fit_transform(
            train_df[col].astype(str)
        )
        encoders[col] = encoder

        # Keep the same encoder for the test set.
        known_values = set(encoder.classes_)
        unseen_values = sorted(
            set(test_df[col].astype(str).unique()) - known_values
        )

        if unseen_values:
            print(
                f"Warning: {col} has {len(unseen_values)} "
                f"unseen test categories: {unseen_values}"
            )

        # Preserve the current project's fallback behavior.
        # Unknown categories are temporarily mapped to the first
        # training category; this limitation should be evaluated.
        test_df[col] = test_df[col].astype(str).map(
            lambda value: value
            if value in known_values
            else encoder.classes_[0]
        )

        test_df[col] = encoder.transform(test_df[col])

    return train_df, test_df, encoders


def main():
    train_df = load_dataset("data/KDDTrain+.txt")
    test_df = load_dataset("data/KDDTest+.txt")

    print("Training records:", len(train_df))
    print("Test records:", len(test_df))

    train_labels = set(train_df["label"].unique())
    test_labels = set(test_df["label"].unique())

    print(
        "Unmapped training labels:",
        sorted(train_labels - set(ATTACK_CATEGORY_MAP)),
    )
    print(
        "Unmapped test labels:",
        sorted(test_labels - set(ATTACK_CATEGORY_MAP)),
    )
    print("Unique training attack labels:", len(train_labels))
    print("Unique test attack labels:", len(test_labels))

    # Convert original attack names into the five target categories.
    y_train = map_attack_labels(train_df["label"], "training data")
    y_test = map_attack_labels(test_df["label"], "test data")

    print("\nTraining class distribution:")
    print(y_train.value_counts().reindex(CLASS_LABELS, fill_value=0))

    print("\nTest class distribution:")
    print(y_test.value_counts().reindex(CLASS_LABELS, fill_value=0))

    # Fit feature encoders using training data only.
    train_df, test_df, encoders = encode_categorical_features(
        train_df, test_df
    )

    X_train = train_df[FEATURE_ORDER]
    X_test = test_df[FEATURE_ORDER]

    # Train directly on the five categories.
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )

    clf.fit(X_train, y_train)

    # Five-class evaluation.
    predictions = clf.predict(X_test)

    print("\n========== FIVE-CLASS EVALUATION ==========")
    print(
        classification_report(
            y_test,
            predictions,
            labels=CLASS_LABELS,
            zero_division=0,
            digits=4,
        )
    )

    # Binary normal-versus-malicious evaluation.
    y_test_binary = y_test != "normal"
    predictions_binary = predictions != "normal"

    print("\n========== BINARY EVALUATION ==========")
    print(
        classification_report(
            y_test_binary,
            predictions_binary,
            labels=[False, True],
            target_names=["normal", "malicious"],
            zero_division=0,
            digits=4,
        )
    )

    # Save artifacts.
    os.makedirs("artifacts", exist_ok=True)

    joblib.dump(clf, "artifacts/model.joblib")
    joblib.dump(encoders, "artifacts/encoders.joblib")

    print("\nSaved artifacts/model.joblib")
    print("Saved artifacts/encoders.joblib")


if __name__ == "__main__":
    main()
