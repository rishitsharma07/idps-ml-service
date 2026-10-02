from pydantic import BaseModel

class TrafficRecord(BaseModel):
    source_ip: str
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: float
    dst_bytes: float
    count: float
    srv_count: float
    serror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    dst_host_count: float
    dst_host_srv_count: float
    
class ClassificationResult(BaseModel):
    source_ip: str
    prediction: str
    is_malicious: bool
    confidence: float