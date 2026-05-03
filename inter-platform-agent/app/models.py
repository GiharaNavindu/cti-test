from pydantic import BaseModel, Field
from typing import List, Optional
import uuid

class STIXIndicator(BaseModel):
    type: str = "indicator"
    id: str
    created: str
    modified: str
    name: str
    description: Optional[str] = None
    indicator_types: List[str]
    pattern: str
    pattern_type: str = "stix"
    valid_from: str


class STIXBundle(BaseModel):
    """Official STIX 2.1 Bundle format for TAXII transport."""

    type: str = "bundle"
    id: str = Field(default_factory=lambda: f"bundle--{uuid.uuid4()}")
    objects: List[STIXIndicator]