from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from uuid import UUID
from database.initialization import get_db
from database.models import EmployeeModel, TeamModel, TaskModel, EmployeeRefreshTokenModel
from security.tokens import create_tokens, get_user_from_access_token, hash_refresh_token
from security.passwords import hash_password, verify_password
from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime, timezone
from typing import Optional
from math import ceil

router = APIRouter(prefix="/api/v1/employee", tags=["Employee"])

# ─── Schemas ────────────────────────────────────────────────────────────────

class RegisterSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

class LoginSchema(BaseModel):
    email: EmailStr
    password: str

class RefreshTokenSchema(BaseModel):
    refresh_token: str

class ChangePasswordSchema(BaseModel):
    old_password: str
    new_password: str

    @field_validator("new_password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

class JoinTeamSchema(BaseModel):
    team_id: UUID

class UpdateTaskStatusSchema(BaseModel):
    status: str

    @field_validator("status")
    def validate_status(cls, v):
        if v not in ("pending", "in_progress", "completed"):
            raise ValueError("Status must be pending, in_progress or completed")
        return v

# ─── Auth ────────────────────────────────────────────────────────────────────

@router.post("/register", summary="Register a new employee")
async def register(body: RegisterSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(EmployeeModel).where(EmployeeModel.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    employee = EmployeeModel(
        email=body.email,
        hashed_password=hash_password(body.password)
    )
    db.add(employee)
    await db.flush()

    tokens = await create_tokens(employee.id, role="employee", db=db)
    await db.commit()
    return {"employee_id": employee.id, **tokens}


@router.post("/login", summary="Login as employee")
async def login(body: LoginSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(EmployeeModel).where(EmployeeModel.email == body.email))
    employee = result.scalar_one_or_none()

    if not employee or not verify_password(employee.hashed_password, body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    tokens = await create_tokens(employee.id, role="employee", db=db)
    return tokens


@router.post("/refresh", summary="Refresh access token")
async def refresh(body: RefreshTokenSchema, db: AsyncSession = Depends(get_db)):
    token_hash = hash_refresh_token(body.refresh_token)

    result = await db.execute(
        select(EmployeeRefreshTokenModel).where(
            EmployeeRefreshTokenModel.token_hash == token_hash,
            EmployeeRefreshTokenModel.is_revoked == False
        )
    ).with_for_update()

    db_token = result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if db_token.expires_at < datetime.now(tz=timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    db_token.is_revoked = True
    await db.commit()

    tokens = await create_tokens(db_token.employee_id, role="employee", db=db)
    return tokens


@router.post("/logout", summary="Logout employee")
async def logout(
    body: RefreshTokenSchema,
    db: AsyncSession = Depends(get_db),
    employee: EmployeeModel = Depends(get_user_from_access_token)
):
    token_hash = hash_refresh_token(body.refresh_token)

    result = await db.execute(
        select(EmployeeRefreshTokenModel).where(
            EmployeeRefreshTokenModel.token_hash == token_hash,
            EmployeeRefreshTokenModel.employee_id == employee.id
        )
    )
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")

    db_token.is_revoked = True
    await db.commit()
    return {"detail": "Logged out successfully"}


@router.patch("/change-password", summary="Change employee password")
async def change_password(
    body: ChangePasswordSchema,
    db: AsyncSession = Depends(get_db),
    employee: EmployeeModel = Depends(get_user_from_access_token)
):
    if not verify_password(employee.hashed_password, body.old_password):
        raise HTTPException(status_code=401, detail="Old password is incorrect")

    employee.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"detail": "Password changed successfully"}


# ─── Team ────────────────────────────────────────────────────────────────────

@router.post("/team/join", summary="Join a team via UUID")
async def join_team(
    body: JoinTeamSchema,
    db: AsyncSession = Depends(get_db),
    employee: EmployeeModel = Depends(get_user_from_access_token)
):
    if employee.team_id:
        raise HTTPException(status_code=400, detail="You are already in a team, exit first")

    result = await db.execute(select(TeamModel).where(TeamModel.id == body.team_id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")

    employee.team_id = team.id
    await db.commit()
    return {"detail": "Joined team successfully", "team_id": team.id}


@router.post("/team/exit", summary="Exit current team")
async def exit_team(
    db: AsyncSession = Depends(get_db),
    employee: EmployeeModel = Depends(get_user_from_access_token)
):
    if not employee.team_id:
        raise HTTPException(status_code=400, detail="You are not in a team")

    # Unassign all tasks
    result = await db.execute(
        select(TaskModel).where(TaskModel.employee_id == employee.id)
    )
    tasks = result.scalars().all()
    for task in tasks:
        task.employee_id = None

    employee.team_id = None
    await db.commit()
    return {"detail": "Exited team successfully, tasks unassigned"}


# ─── Tasks ───────────────────────────────────────────────────────────────────

@router.get("/tasks", summary="Get assigned tasks with filtering and pagination")
async def get_tasks(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[str] = Query(None, description="Filter by status: pending, in_progress, completed"),
    db: AsyncSession = Depends(get_db),
    employee: EmployeeModel = Depends(get_user_from_access_token)
):
    if not employee.team_id:
        raise HTTPException(status_code=400, detail="You are not in a team")

    query = select(TaskModel).where(TaskModel.employee_id == employee.id)

    if status:
        if status not in ("pending", "in_progress", "completed"):
            raise HTTPException(status_code=400, detail="Invalid status filter")
        query = query.where(TaskModel.status == status)

    total = await db.execute(select(func.count()).select_from(query.subquery()))
    total_count = total.scalar()

    offset = (page - 1) * limit
    result = await db.execute(query.offset(offset).limit(limit))
    tasks = result.scalars().all()


    return {
        "page": page,
        "limit": limit,
        "total": total_count,
        "total_pages": ceil(total_count / limit) if total_count else 0,
        "tasks": [
            {
                "id": t.id,
                "taskname": t.taskname,
                "task_description": t.task_description,
                "status": t.status,
                "deadline": t.deadline,
                "created_at": t.created_at,
                "completed_at": t.completed_at
            }
            for t in tasks
        ]
    }


@router.patch("/tasks/{task_id}/status", summary="Update task status")
async def update_task_status(
    task_id: UUID,
    body: UpdateTaskStatusSchema,
    db: AsyncSession = Depends(get_db),
    employee: EmployeeModel = Depends(get_user_from_access_token)
):
    if not employee.team_id:
        raise HTTPException(status_code=400, detail="You are not in a team")

    result = await db.execute(
        select(TaskModel).where(
            TaskModel.id == task_id,
            TaskModel.employee_id == employee.id
        )
    )
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or not assigned to you")

    task.status = body.status
    if body.status == "completed" and not task.completed_at:
        task.completed_at = datetime.now(tz=timezone.utc)
    elif body.status != "completed":
        task.completed_at = None

    await db.commit()
    return {"detail": "Task status updated"}