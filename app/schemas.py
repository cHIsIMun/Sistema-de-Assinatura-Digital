from pydantic import BaseModel, Field

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=20)
    first_name: str = Field(..., min_length=1, max_length=20)
    last_name: str = Field(..., min_length=1, max_length=20)
    password: str = Field(..., min_length=5)

class UserLogin(BaseModel):
    username: str
    password: str
