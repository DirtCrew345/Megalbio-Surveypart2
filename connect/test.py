import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from database import create_db_and_tables, engine
from models import LoginSession, Users
from security import hash_password, hash_token, new_session_token, verify_password

SESSION_SECONDS = 7 * 24 * 60 * 60  # users stay logged in for 7 days


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)

origins = [
    "http://localhost:3000",  # React development server
    "https://example.com",    # Production frontend
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----- What the browser sends us -----

class RegisterRequest(BaseModel):
    name: str = Field(min_length=3, max_length=30, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    name: str = Field(min_length=1, max_length=30)
    password: str = Field(min_length=1, max_length=128)


# ----- Helpers -----

def get_token(authorization: str | None) -> str | None:
    """Return the token from an 'Authorization: Bearer <token>' header, or None."""
    if authorization and authorization.startswith("Bearer "):
        return authorization.removeprefix("Bearer ").strip()
    return None


def get_current_user(authorization: str | None = Header(default=None)) -> dict:
    """Add user: dict = Depends(get_current_user) to any route that needs a logged-in user."""
    token = get_token(authorization)
    if token is None:
        raise HTTPException(status_code=401, detail="Please log in first")

    with Session(engine) as session:
        login = session.exec(
            select(LoginSession).where(LoginSession.token_hash == hash_token(token))
        ).first()
        if login is None or login.expires_at < int(time.time()):
            raise HTTPException(status_code=401, detail="Please log in again")

        user = session.get(Users, login.user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="Please log in again")
        return {"id": user.id, "name": user.name}


# ----- Routes -----

@app.get("/")
def root():
    return {"message": "Hello World"}


@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest):
    with Session(engine) as session:
        existing = session.exec(select(Users).where(Users.name == data.name)).first()
        if existing is not None:
            raise HTTPException(status_code=409, detail="That username is already taken")

        user = Users(name=data.name, password=hash_password(data.password))
        session.add(user)
        try:
            session.commit()
        except IntegrityError:
            # Another request took the same name at the same moment
            session.rollback()
            raise HTTPException(status_code=409, detail="That username is already taken")

        session.refresh(user)
        return {"status": "success", "user": {"id": user.id, "name": user.name}}


@app.post("/login")
def login(data: LoginRequest):
    with Session(engine) as session:
        user = session.exec(select(Users).where(Users.name == data.name)).first()

        # Same message for "no such user" and "wrong password", so this route
        # can't be used to find out which usernames exist
        if user is None or not verify_password(data.password, user.password):
            raise HTTPException(status_code=401, detail="Wrong username or password")

        token = new_session_token()
        session.add(LoginSession(
            user_id=user.id,
            token_hash=hash_token(token),
            expires_at=int(time.time()) + SESSION_SECONDS,
        ))
        session.commit()

        return {
            "status": "success",
            "token": token,
            "user": {"id": user.id, "name": user.name},
        }


@app.post("/logout")
def logout(authorization: str | None = Header(default=None)):
    token = get_token(authorization)
    if token is not None:
        with Session(engine) as session:
            rows = session.exec(
                select(LoginSession).where(LoginSession.token_hash == hash_token(token))
            ).all()
            for row in rows:
                session.delete(row)
            session.commit()
    return {"status": "success", "message": "Logged out"}


@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    return {"status": "success", "user": user}


@app.get("/users/{user_id}")
def read_user(user_id: int):
    with Session(engine) as session:
        user = session.get(Users, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        # Only safe fields. The password hash never leaves the server.
        return {"id": user.id, "name": user.name}
