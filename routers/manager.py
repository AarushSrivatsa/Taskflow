import re

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from uuid import UUID
from database.initialization import get_db
from database.models import ManagerModel, EmployeeModel, TeamModel, TaskModel, ManagerRefreshTokenModel
from security.tokens import create_tokens, get_user_from_access_token, hash_refresh_token
from security.passwords import hash_password, verify_password
from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime, timezone
from typing import Optional, Literal

router = APIRouter(prefix="/api/v1/manager", tags=["Manager"])


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

class CreateTaskSchema(BaseModel):
    taskname: str
    task_description: str
    deadline: datetime
    employee_id: Optional[UUID] = None

    @field_validator("taskname")
    def validate_taskname(cls, v):
        if len(v.strip()) < 3:
            raise ValueError("Task name must be at least 3 characters")
        return v.strip()

    @field_validator("deadline")
    def validate_deadline(cls, v):
        if v < datetime.now(tz=timezone.utc):
            raise ValueError("Deadline cannot be in the past")
        return v

class UpdateTaskSchema(BaseModel):
    taskname: Optional[str] = None
    task_description: Optional[str] = None
    deadline: Optional[datetime] = None
    employee_id: Optional[UUID] = None
    status: Optional[Literal["pending", "in_progress", "completed"]] = None

    @field_validator("deadline")
    def validate_deadline(cls, v):
        if v and v < datetime.now(tz=timezone.utc):
            raise ValueError("Deadline cannot be in the past")
        return v


# ─── Auth ────────────────────────────────────────────────────────────────────

@router.post("/register", summary="Register a new manager")
async def register(body: RegisterSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ManagerModel).where(ManagerModel.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    manager = ManagerModel(
        email=body.email,
        hashed_password=hash_password(body.password)
    )
    db.add(manager)
    await db.commit()
    await db.refresh(manager)

    tokens = await create_tokens(manager.id, role="manager", db=db)
    return {"manager_id": manager.id, **tokens}


@router.post("/login", summary="Login as manager")
async def login(body: LoginSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ManagerModel).where(ManagerModel.email == body.email))
    manager = result.scalar_one_or_none()

    if not manager or not verify_password(manager.hashed_password, body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    tokens = await create_tokens(manager.id, role="manager", db=db)
    return tokens


@router.post("/refresh", summary="Refresh access token")
async def refresh(body: RefreshTokenSchema, db: AsyncSession = Depends(get_db)):
    token_hash = hash_refresh_token(body.refresh_token)

    result = await db.execute(
        select(ManagerRefreshTokenModel).where(
            ManagerRefreshTokenModel.token_hash == token_hash,
            ManagerRefreshTokenModel.is_revoked == False
        )
    ).with_for_update()

    db_token = result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    if db_token.expires_at < datetime.now(tz=timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    db_token.is_revoked = True
    await db.commit()

    tokens = await create_tokens(db_token.manager_id, role="manager", db=db)
    return tokens

@router.post("/logout", summary="Logout manager")
async def logout(
    body: RefreshTokenSchema,
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    token_hash = hash_refresh_token(body.refresh_token)

    result = await db.execute(
        select(ManagerRefreshTokenModel).where(
            ManagerRefreshTokenModel.token_hash == token_hash,
            ManagerRefreshTokenModel.manager_id == manager.id
        )
    )
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")

    db_token.is_revoked = True
    await db.commit()
    return {"detail": "Logged out successfully"}


@router.patch("/change-password", summary="Change manager password")
async def change_password(
    body: ChangePasswordSchema,
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    if not verify_password(manager.hashed_password, body.old_password):
        raise HTTPException(status_code=401, detail="Old password is incorrect")

    manager.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"detail": "Password changed successfully"}


# ─── Team ────────────────────────────────────────────────────────────────────

@router.post("/team", summary="Create a team")
async def create_team(
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="You already have a team")

    team = TeamModel(manager_id=manager.id)
    db.add(team)
    await db.commit()
    await db.refresh(team)
    return {"team_id": team.id, "created_at": team.created_at}


@router.get("/team", summary="Get your team details and UUID")
async def get_team(
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="You don't have a team yet")

    return {"team_id": team.id, "created_at": team.created_at}


@router.get("/team/members", summary="Get all team members with pagination")
async def get_members(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="You don't have a team yet")

    offset = (page - 1) * limit
    result = await db.execute(
        select(EmployeeModel)
        .where(EmployeeModel.team_id == team.id)
        .offset(offset)
        .limit(limit)
    )
    members = result.scalars().all()

    total = await db.execute(
        select(func.count()).where(EmployeeModel.team_id == team.id)
    )
    total_count = total.scalar()

    return {
        "page": page,
        "limit": limit,
        "total": total_count,
        "members": [{"id": m.id, "email": m.email} for m in members]
    }


@router.delete("/team/members/{employee_id}", summary="Remove a member from team")
async def remove_member(
    employee_id: UUID,
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="You don't have a team yet")

    result = await db.execute(
        select(EmployeeModel).where(
            EmployeeModel.id == employee_id,
            EmployeeModel.team_id == team.id
        )
    )
    employee = result.scalar_one_or_none()
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found in your team")

    # Unassign all their tasks
    task_result = await db.execute(
        select(TaskModel).where(
            TaskModel.employee_id == employee_id,
            TaskModel.team_id == team.id
        )
    )
    tasks = task_result.scalars().all()
    for task in tasks:
        task.employee_id = None

    employee.team_id = None
    await db.commit()
    return {"detail": "Member removed and tasks unassigned"}


# ─── Tasks ───────────────────────────────────────────────────────────────────

@router.post("/tasks", summary="Create a task")
async def create_task(
    body: CreateTaskSchema,
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="You don't have a team yet")

    # Validate employee belongs to manager's team
    if body.employee_id:
        result = await db.execute(
            select(EmployeeModel).where(
                EmployeeModel.id == body.employee_id,
                EmployeeModel.team_id == team.id
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Employee not in your team")

    task = TaskModel(
        taskname=body.taskname,
        task_description=body.task_description,
        deadline=body.deadline,
        employee_id=body.employee_id,
        manager_id=manager.id,
        team_id=team.id
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return {"task_id": task.id, "created_at": task.created_at}


@router.get("/tasks", summary="Get all team tasks with filtering and pagination")
async def get_tasks(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    status: Optional[str] = Query(None, description="Filter by status: pending, in_progress, completed"),
    employee_id: Optional[UUID] = Query(None, description="Filter by assigned employee"),
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="You don't have a team yet")

    query = select(TaskModel).where(TaskModel.team_id == team.id)

    if status:
        if status not in ("pending", "in_progress", "completed"):
            raise HTTPException(status_code=400, detail="Invalid status filter")
        query = query.where(TaskModel.status == status)

    if employee_id:
        query = query.where(TaskModel.employee_id == employee_id)

    total = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total_count = total.scalar()

    offset = (page - 1) * limit
    result = await db.execute(query.offset(offset).limit(limit))
    tasks = result.scalars().all()

    return {
        "page": page,
        "limit": limit,
        "total": total_count,
        "tasks": [
            {
                "id": t.id,
                "taskname": t.taskname,
                "task_description": t.task_description,
                "status": t.status,
                "deadline": t.deadline,
                "employee_id": t.employee_id,
                "created_at": t.created_at,
                "completed_at": t.completed_at
            }
            for t in tasks
        ]
    }


@router.patch("/tasks/{task_id}", summary="Update a task")
async def update_task(
    task_id: UUID,
    body: UpdateTaskSchema,
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="You don't have a team yet")

    result = await db.execute(
        select(TaskModel).where(TaskModel.id == task_id, TaskModel.team_id == team.id)
    )
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if body.employee_id:
        result = await db.execute(
            select(EmployeeModel).where(
                EmployeeModel.id == body.employee_id,
                EmployeeModel.team_id == team.id
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Employee not in your team")

    if body.taskname is not None:
        task.taskname = body.taskname
    if body.task_description is not None:
        task.task_description = body.task_description
    if body.deadline is not None:
        task.deadline = body.deadline
    if body.employee_id is not None:
        task.employee_id = body.employee_id
    if body.status is not None:
        task.status = body.status
        if body.status == "completed" and not task.completed_at:
            task.completed_at = datetime.now(tz=timezone.utc)
        elif body.status != "completed":
            task.completed_at = None

    await db.commit()
    return {"detail": "Task updated"}


@router.delete("/tasks/{task_id}", summary="Delete a task")
async def delete_task(
    task_id: UUID,
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="You don't have a team yet")

    result = await db.execute(
        select(TaskModel).where(TaskModel.id == task_id, TaskModel.team_id == team.id)
    )
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    await db.delete(task)
    await db.commit()
    return {"detail": "Task deleted"}

# ─── Dashboard ───────────────────────────────────────────────────────────────

@router.get("/dashboard", summary="Get team task stats")
async def dashboard(
    db: AsyncSession = Depends(get_db),
    manager: ManagerModel = Depends(get_user_from_access_token)
):
    result = await db.execute(select(TeamModel).where(TeamModel.manager_id == manager.id))
    team = result.scalar_one_or_none()
    if not team:
        raise HTTPException(status_code=404, detail="You don't have a team yet")

    now = datetime.now(tz=timezone.utc)

    total = await db.execute(select(func.count()).where(TaskModel.team_id == team.id))
    completed = await db.execute(select(func.count()).where(TaskModel.team_id == team.id, TaskModel.status == "completed"))
    pending = await db.execute(select(func.count()).where(TaskModel.team_id == team.id, TaskModel.status == "pending"))
    in_progress = await db.execute(select(func.count()).where(TaskModel.team_id == team.id, TaskModel.status == "in_progress"))
    overdue = await db.execute(
        select(func.count()).where(
            TaskModel.team_id == team.id,
            TaskModel.deadline < now,
            TaskModel.status != "completed"
        )
    )
    members = await db.execute(select(func.count()).where(EmployeeModel.team_id == team.id))

    return {
        "total_tasks": total.scalar(),
        "completed": completed.scalar(),
        "pending": pending.scalar(),
        "in_progress": in_progress.scalar(),
        "overdue": overdue.scalar(),
        "total_members": members.scalar()
    }