import asyncio
from sqlalchemy.orm import relationship
from database.initialization import engine, Base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, DateTime, ForeignKey, text, Boolean
from sqlalchemy.sql import func


class EmployeeModel(Base):
    __tablename__ = "employee"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    team_id = Column(UUID(as_uuid=True), ForeignKey("team.id", ondelete="SET NULL"), nullable=True, index=True)
    team = relationship("TeamModel", back_populates="members")
    tasks = relationship("TaskModel", back_populates="members")


class ManagerModel(Base):
    __tablename__ = "manager"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    team = relationship("TeamModel", back_populates="manager", uselist=False)  # ← one team per manager
    tasks = relationship("TaskModel", back_populates="manager")


class TeamModel(Base):
    __tablename__ = "team"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    manager_id = Column(UUID(as_uuid=True), ForeignKey("manager.id", ondelete="CASCADE"), nullable=False, index=True)
    manager = relationship("ManagerModel", back_populates="team")
    members = relationship("EmployeeModel", back_populates="team")
    tasks = relationship("TaskModel", back_populates="team")


class TaskModel(Base):
    __tablename__ = "task"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    taskname = Column(String, nullable=False)
    task_description = Column(String, nullable=False)
    status = Column(String, default="pending", nullable=False)  # ← pending, in_progress, completed
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    deadline = Column(DateTime(timezone=True), nullable=False)
    manager_id = Column(UUID(as_uuid=True), ForeignKey("manager.id", ondelete="CASCADE"), nullable=False, index=True)
    manager = relationship("ManagerModel", back_populates="tasks")
    employee_id = Column(UUID(as_uuid=True), ForeignKey("employee.id", ondelete="SET NULL"), nullable=True, index=True)
    members = relationship("EmployeeModel", back_populates="tasks")
    team_id = Column(UUID(as_uuid=True), ForeignKey("team.id", ondelete="CASCADE"), nullable=False, index=True)
    team = relationship("TeamModel", back_populates="tasks")


class EmployeeRefreshTokenModel(Base):
    __tablename__ = "employee_refresh_tokens"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    employee_id = Column(UUID(as_uuid=True), ForeignKey("employee.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    employee = relationship("EmployeeModel")


class ManagerRefreshTokenModel(Base):
    __tablename__ = "manager_refresh_tokens"
    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    manager_id = Column(UUID(as_uuid=True), ForeignKey("manager.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    manager = relationship("ManagerModel")


async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Tables created in Database!")


if __name__ == "__main__":
    asyncio.run(create_tables())