from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import create_engine, Column, Integer, String, Boolean, JSON, BigInteger, ForeignKey
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional


DATABASE_URL = "postgresql://postgres:Admin123@localhost/organisation"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    profile = Column(JSON, default={})
    status = Column(Integer, default=0)
    settings = Column(JSON, default={})
    created_at = Column(BigInteger, nullable=True)
    updated_at = Column(BigInteger, nullable=True)


class Organization(Base):
    __tablename__ = "organization"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    status = Column(Integer, default=0)
    personal = Column(Boolean, default=False)
    settings = Column(JSON, default={})
    created_at = Column(BigInteger, nullable=True)
    updated_at = Column(BigInteger, nullable=True)


class Member(Base):
    __tablename__ = "member"
    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    status = Column(Integer, default=0)
    settings = Column(JSON, default={})
    created_at = Column(BigInteger, nullable=True)
    updated_at = Column(BigInteger, nullable=True)


class Role(Base):
    __tablename__ = "role"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(String)
    org_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    profile: dict = {}

class OrganizationCreate(BaseModel):
    name: str

class MemberCreate(BaseModel):
    org_id: int
    role_id: int

class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

app = FastAPI()

Base.metadata.create_all(bind=engine)

@app.post("/signup")
def signup(user: UserCreate, org: OrganizationCreate, db: SessionLocal = Depends(get_db)):
    # Check if the user already exists
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    # Create new user
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, password=hashed_password, profile=user.profile)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create organization and make user the owner
    new_org = Organization(name=org.name)
    db.add(new_org)
    db.commit()
    db.refresh(new_org)
    
    # Add member entry for user in the organization with owner role
    owner_role = db.query(Role).filter(Role.name == "owner", Role.org_id == new_org.id).first()
    if not owner_role:
        owner_role = Role(name="owner", org_id=new_org.id)
        db.add(owner_role)
        db.commit()
        db.refresh(owner_role)
    
    new_member = Member(user_id=new_user.id, org_id=new_org.id, role_id=owner_role.id)
    db.add(new_member)
    db.commit()
    
    return {"message": "User signed up and organization created successfully"}

@app.post("/signin", response_model=Token)
def signin(email: str, password: str, db: SessionLocal = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/reset-password")
def reset_password(email: str, new_password: str, db: SessionLocal = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    user.password = get_password_hash(new_password)
    db.commit()
    return {"message": "Password reset successfully"}


@app.post("/invite-member")
def invite_member(email: str, org_id: int, role_id: int, db: SessionLocal = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    new_member = Member(user_id=user.id, org_id=org_id, role_id=role_id)
    db.add(new_member)
    db.commit()
    return {"message": "User invited to the organization"}

@app.put("/update-member-role")
def update_member_role(member_id: int, role_id: int, db: SessionLocal = Depends(get_db)):
    member = db.query(Member).filter(Member.id == member_id).first()
    if not member:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    
    member.role_id = role_id
    db.commit()
    return {"message": "Member role updated successfully"}

@app.delete("/delete-member/{member_id}")
def delete_member(member_id: int, db: SessionLocal = Depends(get_db)):
    member = db.query(Member).filter(Member.id == member_id).first()
    if not member:
        raise HTTPException(status_code=404, detail="Member not found")

    db.delete(member)
    db.commit()

    return {"message": "Member deleted successfully!"}


@app.get("/stats/role-wise-users")
def get_role_wise_users(db: SessionLocal = Depends()):
    result = db.query(Role.name, func.count(Member.user_id).label('user_count'))\
               .join(Member, Role.id == Member.role_id)\
               .group_by(Role.name)\
               .all()
    
    return [{"role": role.name, "user_count": user_count} for role, user_count in result]

@app.get("/stats/org-wise-members")
def get_org_wise_members(db: SessionLocal = Depends()):
    result = db.query(Organization.name, func.count(Member.user_id).label('member_count'))\
               .join(Member, Organization.id == Member.org_id)\
               .group_by(Organization.name)\
               .all()

    return [{"organization": org_name, "member_count": member_count} for org_name, member_count in result]

@app.get("/stats/org-wise-role-wise-users")
def get_org_role_wise_users(db: SessionLocal = Depends()):
    result = db.query(Organization.name, Role.name, func.count(Member.user_id).label('user_count'))\
               .join(Member, Organization.id == Member.org_id)\
               .join(Role, Role.id == Member.role_id)\
               .group_by(Organization.name, Role.name)\
               .all()

    return [{"organization": org_name, "role": role_name, "user_count": user_count} 
            for org_name, role_name, user_count in result]
    
@app.get("/stats/org-wise-role-wise-users-filtered")
def get_org_role_wise_users_filtered(
    from_time: int = None,
    to_time: int = None,
    status: int = None,
    db: SessionLocal = Depends()
):
    query = db.query(Organization.name, Role.name, func.count(Member.user_id).label('user_count'))\
              .join(Member, Organization.id == Member.org_id)\
              .join(Role, Role.id == Member.role_id)\
              .group_by(Organization.name, Role.name)
    
    if from_time:
        query = query.filter(Member.created_at >= from_time)
    if to_time:
        query = query.filter(Member.created_at <= to_time)
    if status is not None:
        query = query.filter(Member.status == status)

    result = query.all()

    return [{"organization": org_name, "role": role_name, "user_count": user_count} 
            for org_name, role_name, user_count in result]
@app.get("/stats/org-wise-members-filtered")
def get_org_wise_members_filtered(
    from_time: int = None,
    to_time: int = None,
    status: int = None,
    db: SessionLocal = Depends()
):
    query = db.query(Organization.name, func.count(Member.user_id).label('member_count'))\
              .join(Member, Organization.id == Member.org_id)\
              .group_by(Organization.name)

    if from_time:
        query = query.filter(Member.created_at >= from_time)
    if to_time:
        query = query.filter(Member.created_at <= to_time)
    if status is not None:
        query = query.filter(Member.status == status)

    result = query.all()

    return [{"organization": org_name, "member_count": member_count} for org_name, member_count in result]