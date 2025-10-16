from __future__ import annotations

import secrets
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER, HTTP_401_UNAUTHORIZED

from app.api.deps import get_db
from app.core.settings import get_settings
from app.db import License, LicenseStatus
from app.services.license_service import LicenseService

router = APIRouter()
settings = get_settings()
security = HTTPBasic()

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))

STATUS_LABELS = {
    LicenseStatus.UNUSED.value: "未使用",
    LicenseStatus.ACTIVE.value: "已激活",
    LicenseStatus.REVOKED.value: "已撤销",
    LicenseStatus.EXPIRED.value: "已过期",
}


def require_admin(credentials: HTTPBasicCredentials = Depends(security)) -> HTTPBasicCredentials:
    username_match = secrets.compare_digest(credentials.username, settings.admin_username)
    password_match = secrets.compare_digest(credentials.password, settings.admin_password)
    if not (username_match and password_match):
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials


@router.get("/licenses")
def licenses_page(
    request: Request,
    status: str = "all",
    limit: int = 20,
    message: str | None = None,
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    stmt = select(License).order_by(License.created_at.desc())
    if status != "all":
        stmt = stmt.where(License.status == status)
    if limit > 0:
        stmt = stmt.limit(limit)

    license_rows = []
    for license_obj in db.scalars(stmt).all():
        latest_seen = None
        if license_obj.activations:
            latest_seen = max(
                (activation.last_seen for activation in license_obj.activations if activation.last_seen),
                default=None,
            )
        license_rows.append((license_obj, latest_seen))
    statuses = [("all", "全部"), *[(s.value, STATUS_LABELS.get(s.value, s.value)) for s in LicenseStatus]]

    return templates.TemplateResponse(
        "admin/licenses.html",
        {
            "request": request,
            "licenses": license_rows,
            "status": status,
            "limit": limit,
            "statuses": statuses,
            "message": message,
            "status_labels": STATUS_LABELS,
        },
    )


@router.post("/licenses/revoke")
def revoke_license(
    request: Request,
    card_code: str = Form(...),
    status: str = Form("all"),
    limit: int = Form(20),
    db: Session = Depends(get_db),
    _: HTTPBasicCredentials = Depends(require_admin),
):
    service = LicenseService(db)
    success = service.revoke(card_code)
    if success:
        msg = f"卡密 {card_code} 已撤销"
    else:
        msg = f"未找到卡密 {card_code}"

    query = urlencode({"status": status, "limit": limit, "message": msg})
    return RedirectResponse(url=f"/admin/licenses?{query}", status_code=HTTP_303_SEE_OTHER)
