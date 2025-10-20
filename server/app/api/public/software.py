from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas import SoftwarePackageListResponse, SoftwarePackageResponse, SoftwareSlotResponse
from app.services.licensing import SoftwareService

router = APIRouter(prefix="/software", tags=["software"])


@router.get("/slots", response_model=List[SoftwareSlotResponse])
def list_slots(db: Session = Depends(get_db)) -> List[SoftwareSlotResponse]:
    service = SoftwareService(db)
    slots = service.list_slots()
    responses: List[SoftwareSlotResponse] = []
    for slot in slots:
        current_package = slot.current_package
        responses.append(
            SoftwareSlotResponse(
                code=slot.code,
                name=slot.name,
                status=slot.status,
                product_line=slot.product_line,
                channel=slot.channel,
                gray_ratio=slot.gray_ratio,
                notes=slot.notes,
                current_package_id=current_package.id if current_package else None,
                current_package_version=current_package.version if current_package else None,
                updated_at=slot.updated_at,
            )
        )
    return responses


@router.get("/packages", response_model=SoftwarePackageListResponse)
def list_packages(
    slot_code: str = Query(..., min_length=2, max_length=64),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query("active", description="Filter by package status, e.g. active/draft/retired/all"),
    db: Session = Depends(get_db),
) -> SoftwarePackageListResponse:
    service = SoftwareService(db)
    slot = service.get_slot_by_code(slot_code)
    if not slot:
        raise HTTPException(status_code=404, detail="slot_not_found")

    packages = service.list_packages(slot_id=slot.id, limit=limit)
    if status and status.lower() != "all":
        normalized = status.lower()
        packages = [pkg for pkg in packages if pkg.status.lower() == normalized]

    responses = [
        SoftwarePackageResponse(
            id=pkg.id,
            version=pkg.version,
            status=pkg.status,
            file_url=pkg.file_url,
            checksum=pkg.checksum,
            release_notes=pkg.release_notes,
            is_critical=pkg.is_critical,
            promoted_at=pkg.promoted_at,
            created_at=pkg.created_at,
        )
        for pkg in packages
    ]

    return SoftwarePackageListResponse(slot_code=slot.code, items=responses)
