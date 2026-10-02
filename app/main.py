from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from app.schemas import TrafficRecord, ClassificationResult
from app.model import model_wrapper


@asynccontextmanager
async def lifespan(app: FastAPI):
    model_wrapper.load()
    yield


app = FastAPI(title="IDPS ML Classification Service", version="1.0", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": model_wrapper.loaded}


@app.post("/classify", response_model=ClassificationResult)
def classify(record: TrafficRecord):
    if not model_wrapper.loaded:
        raise HTTPException(status_code=503, detail="Model not loaded yet — train and place artifacts/model.joblib")
    try:
        result = model_wrapper.predict(record.model_dump())
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing/invalid feature: {e}")

    return ClassificationResult(
        source_ip=record.source_ip,
        prediction=result["prediction"],
        is_malicious=result["is_malicious"],
        confidence=result["confidence"],
    )