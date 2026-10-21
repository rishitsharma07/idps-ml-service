
import os
import joblib
import pandas as pd

MODEL_PATH = "artifacts/model.joblib"
ENCODERS_PATH = "artifacts/encoders.joblib"

FEATURE_ORDER = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "count", "srv_count", "serror_rate", "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count",
]

ATTACK_CATEGORY_MAP = {
    "normal": "normal",
    "neptune": "dos",
    "smurf": "dos",
    "back": "dos",
    "teardrop": "dos",
    "pod": "dos",
    "land": "dos",
    "apache2": "dos",
    "udpstorm": "dos",
    "processtable": "dos",
    "worm": "dos",
    "mailbomb": "dos",
    "satan": "probe",
    "ipsweep": "probe",
    "nmap": "probe",
    "portsweep": "probe",
    "mscan": "probe",
    "saint": "probe",
    "guess_passwd": "r2l",
    "ftp_write": "r2l",
    "imap": "r2l",
    "phf": "r2l",
    "multihop": "r2l",
    "warezmaster": "r2l",
    "warezclient": "r2l",
    "spy": "r2l",
    "xlock": "r2l",
    "xsnoop": "r2l",
    "snmpguess": "r2l",
    "snmpgetattack": "r2l",
    "httptunnel": "r2l",
    "sendmail": "r2l",
    "named": "r2l",
    "buffer_overflow": "u2r",
    "loadmodule": "u2r",
    "rootkit": "u2r",
    "perl": "u2r",
    "sqlattack": "u2r",
    "xterm": "u2r",
    "ps": "u2r",
}

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

VALID_CATEGORIES = {"normal", "dos", "probe", "r2l", "u2r"}


class ModelWrapper:
    def __init__(self):
        self.model = None
        self.encoders = None
        self.loaded = False

    def load(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.encoders = joblib.load(ENCODERS_PATH)

            # Verify that the model predicts the expected five categories.
            model_classes = set(self.model.classes_)
            if not model_classes.issubset(VALID_CATEGORIES):
                raise ValueError(
                    f"Unexpected model classes: {model_classes}"
                )

            self.loaded = True
        else:
            self.loaded = False

    def _encode(self, record: dict) -> pd.DataFrame:
        row = {col: record[col] for col in FEATURE_ORDER}
        df = pd.DataFrame([row])

        for col in CATEGORICAL_COLS:
            encoder = self.encoders[col]
            known_values = set(encoder.classes_)

            # Keep encoding consistent with training.
            df[col] = df[col].map(
                lambda value: value
                if value in known_values
                else encoder.classes_[0]
            )
            df[col] = encoder.transform(df[col])

        return df

    def predict(self, record: dict):
        if not self.loaded:
            raise RuntimeError(
                "Model not loaded — run train_model.py first"
            )

        X = self._encode(record)

        pred = str(self.model.predict(X)[0])
        probabilities = self.model.predict_proba(X)[0]
        confidence = float(max(probabilities))

        if pred not in VALID_CATEGORIES:
            raise ValueError(f"Unexpected prediction category: {pred}")

        return {
            "prediction": pred,
            "is_malicious": pred != "normal",
            "confidence": confidence,
        }


model_wrapper = ModelWrapper()
