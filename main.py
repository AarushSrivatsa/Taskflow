from fastapi import FastAPI
from routers.employee import router as employee_router
from routers.manager import router as manager_router

app = FastAPI(
    title="Task Management API",
    version="1.0.0",
    description="Role-based task management system for managers and employees"
)

router_list = [employee_router,manager_router]

for router in router_list:
    app.include_router(router)