from sqlmodel import Field, SQLModel


class Users(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    password: str  # holds a salted hash from security.py, never the plain password


class LoginSession(SQLModel, table=True):
    # One row per logged-in browser. Only a hash of the token is stored.
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True)
    token_hash: str = Field(index=True, unique=True)
    expires_at: int  # Unix time in seconds
