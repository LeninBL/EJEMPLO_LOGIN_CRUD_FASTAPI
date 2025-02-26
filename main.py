from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from dotenv import load_dotenv
from fastapi.staticfiles import StaticFiles
import os
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey



# Cargar las variables de entorno desde el archivo .env
load_dotenv()

# Configuración de seguridad
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
DATABASE_URL = os.getenv("DATABASE_URL")


app = FastAPI()
templates = Jinja2Templates(directory="templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuración de la base de datos
engine = create_engine(
    DATABASE_URL,
    pool_size=10,       # Aumenta el tamaño del pool
    max_overflow=20,    # Permite más conexiones adicionales
    pool_timeout=30,    # Tiempo de espera antes de lanzar TimeoutError
    pool_recycle=1800   # Recicla conexiones cada 30 minutos para evitar problemas
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Modelo de usuario en la base de datos
class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

    # Relación uno a uno con user_details
    user_details = relationship("UserDetailsDB", back_populates="user", uselist=False)

# Crear todas las tablas en la base de datos
Base.metadata.create_all(bind=engine)

# Crear la clase para la tabla `user_details`
class UserDetailsDB(Base):
    __tablename__ = "user_details"
    user_id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    dob = Column(String)
    location = Column(String)
    bio = Column(String)

    # Relacionado con el usuario (clave foránea)
    user = relationship("UserDB", back_populates="user_details")

    # Establecer la clave foránea explícita
    user_id = Column(Integer, ForeignKey('users.id'), primary_key=True)

# Relación en UserDB
UserDB.user_details = relationship("UserDetailsDB", uselist=False, back_populates="user")


class User(BaseModel):
    username: str
    hashed_password: str

class UserDetails(BaseModel):
    first_name: str
    last_name: str
    dob: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None

class UserUpdate(BaseModel):
    username: str  
    first_name: str
    last_name: str
    dob: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    current_password: str
    new_password: Optional[str] = None
    confirm_password: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

# Función para verificar la contraseña
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Función para obtener un usuario desde la base de datos
def get_user(db, username: str):
    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user:
        return User(username=user.username, hashed_password=user.hashed_password)
    return None

# Función para obtener los detalles del usuario
def get_user_details(db, user_id: int):
    return db.query(UserDetailsDB).filter(UserDetailsDB.user_id == user_id).first()

# Función para autenticar al usuario
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Función para crear el token de acceso
def create_access_token(data: dict):
    to_encode = data.copy()
    # Incluir timestamp de la última actividad
    to_encode['last_activity'] = datetime.now(timezone.utc).isoformat()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Verificar si la sesión está expirada por inactividad
def is_session_expired(last_activity: str, inactivity_limit_minutes: int = 30):
    last_activity_time = datetime.fromisoformat(last_activity)
    now = datetime.now(timezone.utc)
    inactivity_duration = now - last_activity_time
    return inactivity_duration > timedelta(minutes=inactivity_limit_minutes)


# Ruta para login
@app.post("/token", response_model=Token)
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": user.username})
    response.set_cookie(
        key="access_token",
        value=access_token,  
        httponly=True,
        secure=True,  
        samesite="Lax"
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Ruta de inicio
@app.get("/")
async def read_root(request: Request):
    token = request.cookies.get("access_token")
    session_expired = False  

    if token:
        return RedirectResponse("/users/me")

    session_expired = request.cookies.get("session_expired", "false") == "true"

    response = templates.TemplateResponse("index.html", {
        "request": request,
        "session_expired": session_expired
    })
    
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Rutas protegidas
@app.get("/users/me")
async def read_users_me(request: Request):
    token = request.cookies.get("access_token")

    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        last_activity = payload.get("last_activity")


        if not last_activity or is_session_expired(last_activity):
            response = RedirectResponse("/", status_code=302)
            response.delete_cookie(key="access_token")  
            

            expires_in=datetime.now(timezone.utc) + timedelta(seconds=3) 

            response.set_cookie(
                key="session_expired",
                value="true",
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=3, 
                expires=expires_in  
            )
            return response
        db = SessionLocal()
        user = db.query(UserDB).filter(UserDB.username == username).first()
        user_details = get_user_details(db, user.id)

        # Actualizar el timestamp de la última actividad
        payload['last_activity'] = datetime.now(timezone.utc).isoformat()
        new_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        response = templates.TemplateResponse("welcome.html", {"request": request, "username": f'{user_details.first_name} {user_details.last_name}'})
        response.set_cookie(
            key="access_token",
            value=new_token,
            httponly=True,
            secure=True,
            samesite="Lax"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except JWTError:
        return RedirectResponse("/", status_code=302)

@app.get("/users/me/profile")
async def read_users_me_profile(request: Request):
    token = request.cookies.get("access_token")

    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        last_activity = payload.get("last_activity")


        if not last_activity or is_session_expired(last_activity):
            response = RedirectResponse("/", status_code=302)
            response.delete_cookie(key="access_token")  

            expires_in = datetime.now(timezone.utc) + timedelta(seconds=3)

            response.set_cookie(
                key="session_expired",
                value="true",
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=3,
                expires=expires_in
            )
            return response

 
        db = SessionLocal()
        user = db.query(UserDB).filter(UserDB.username == username).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")


        user_details = get_user_details(db, user.id)

        if not user_details:
            raise HTTPException(status_code=404, detail="User details not found")


        payload['last_activity'] = datetime.now(timezone.utc).isoformat()
        new_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


        response = templates.TemplateResponse(
            "profile.html", {
                "request": request,
                "username": f'{user_details.first_name} {user_details.last_name}',
                "userFullName": user_details.first_name,
                "userLastName": user_details.last_name,
                "userEmail": user.username, 
                "userDOB": user_details.dob,
                "userLocation": user_details.location,
                "userBio": user_details.bio
            }
        )

        response.set_cookie(
            key="access_token",
            value=new_token,
            httponly=True,
            secure=True,
            samesite="Lax"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except JWTError:
        return RedirectResponse("/", status_code=302)
    
@app.put("/users/me/update_profile", response_model=UserDetails)
async def update_user_profile(
    user_update: UserUpdate, 
    db: Session = Depends(get_db),
    request: Request = None
):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user = db.query(UserDB).filter(UserDB.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        

        if not verify_password(user_update.current_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect current password")
        
 
        if user_update.new_password:
            if user_update.new_password != user_update.confirm_password:
                raise HTTPException(status_code=400, detail="Passwords do not match")
            user.hashed_password = pwd_context.hash(user_update.new_password)
        

        user_details = get_user_details(db, user.id)
        if not user_details:
            raise HTTPException(status_code=404, detail="User details not found")
        
        user_details.first_name = user_update.first_name
        user_details.last_name = user_update.last_name
        user_details.dob = user_update.dob
        user_details.location = user_update.location
        user_details.bio = user_update.bio

        db.commit()
        

        payload['last_activity'] = datetime.now(timezone.utc).isoformat()
        new_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        

        response = {"message": "Perfil actualizado con éxito."}  
        return JSONResponse(content=response, status_code=200)  
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

@app.get("/users/me/show")
async def read_users_me(request: Request):
    token = request.cookies.get("access_token")

    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        last_activity = payload.get("last_activity")


        if not last_activity or is_session_expired(last_activity):
            response = RedirectResponse("/", status_code=302)
            response.delete_cookie(key="access_token") 

            expires_in = datetime.now(timezone.utc) + timedelta(seconds=3)

            response.set_cookie(
                key="session_expired",
                value="true",
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=3,
                expires=expires_in
            )
            return response
        
        db = SessionLocal()
        user = db.query(UserDB).filter(UserDB.username == username).first()
        user_details = get_user_details(db, user.id)
        user_name=user_details.first_name
        user_last_name=user_details.last_name
        all_users = db.query(UserDB).all() 

        all_users_with_details = []
        for user in all_users:
            user_details = get_user_details(db, user.id)
            all_users_with_details.append({"user": user, "details": user_details})


        payload['last_activity'] = datetime.now(timezone.utc).isoformat()
        new_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


        response = templates.TemplateResponse("show.html", {
            "request": request, 
            "username": f'{user_name} {user_last_name}', 
            "all_users_with_details": all_users_with_details
        })

        response.set_cookie(
            key="access_token",
            value=new_token,
            httponly=True,
            secure=True,
            samesite="Lax"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except JWTError:
        return RedirectResponse("/", status_code=302)

@app.get("/users/me/register_show")
async def read_users_me(request: Request):
    token = request.cookies.get("access_token")

    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        last_activity = payload.get("last_activity")

        if not last_activity or is_session_expired(last_activity):
            response = RedirectResponse("/", status_code=302)
            response.delete_cookie(key="access_token") 

            expires_in = datetime.now(timezone.utc) + timedelta(seconds=3)

            response.set_cookie(
                key="session_expired",
                value="true",
                httponly=True,
                secure=True,
                samesite="Lax",
                max_age=3,
                expires=expires_in
            )
            return response

        db = SessionLocal()
        user = db.query(UserDB).filter(UserDB.username == username).first()
        user_details = get_user_details(db, user.id)
        user_name=user_details.first_name
        user_last_name=user_details.last_name
        all_users = db.query(UserDB).all()  

        all_users_with_details = []
        for user in all_users:
            user_details = get_user_details(db, user.id)
            all_users_with_details.append({"user": user, "details": user_details})


        payload['last_activity'] = datetime.now(timezone.utc).isoformat()
        new_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


        response = templates.TemplateResponse("register_show.html", {
            "request": request, 
            "username": f'{user_name} {user_last_name}', 
            "all_users_with_details": all_users_with_details
        })

        response.set_cookie(
            key="access_token",
            value=new_token,
            httponly=True,
            secure=True,
            samesite="Lax"
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    except JWTError:
        return RedirectResponse("/", status_code=302)

@app.post("/users/me/create")
def create_user(user: User, user_details: UserDetails, db: Session = Depends(get_db)):

    db_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Usuario ya existe")


    hashed_password = pwd_context.hash(user.hashed_password)


    new_user = UserDB(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)


    new_user_details = UserDetailsDB(
        user_id=new_user.id,
        first_name=user_details.first_name,
        last_name=user_details.last_name,
        dob=user_details.dob,
        location=user_details.location,
        bio=user_details.bio
    )
    db.add(new_user_details)
    db.commit()
    db.refresh(new_user_details)

    return {"message": "Usuario creado exitosamente"}

@app.get("/users/me/{user_id}")
def read_user(user_id: int, db: Session = Depends(get_db)):
    user_details = db.query(UserDetailsDB).filter(UserDetailsDB.user_id == user_id).first()
    if user_details is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    
    return user_details

@app.put("/users/me/{user_id}")
def update_user(user_id: int, user_update: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")


    if not verify_password(user_update.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Contraseña incorrecta")


    if user_update.new_password:
        user.hashed_password = pwd_context.hash(user_update.new_password)

    user_details = db.query(UserDetailsDB).filter(UserDetailsDB.user_id == user_id).first()
    if user_details:
        user_details.first_name = user_update.first_name
        user_details.last_name = user_update.last_name
        user_details.dob = user_update.dob
        user_details.location = user_update.location
        user_details.bio = user_update.bio
        db.commit()
        db.refresh(user_details)

    db.commit()
    db.refresh(user)
    return {"message": "Usuario actualizado exitosamente"}

@app.delete("/users/me/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    db.query(UserDetailsDB).filter(UserDetailsDB.user_id == user_id).delete()
    db.query(UserDB).filter(UserDB.id == user_id).delete()
    db.commit()
    return {"message": "Usuario eliminado exitosamente"}


# Ruta para logout
@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    return RedirectResponse("/", status_code=302, headers={
        "Set-Cookie": "access_token=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"
        
    })

app.mount("/assets", StaticFiles(directory="assets"), name="assets")