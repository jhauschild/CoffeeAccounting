"""The step-up confirm route (owner: admin agent).

`POST /admin/stepup/confirm` is the ONLY route that executes balance-changing admin actions. The entry
forms (payment, adjustment, reversal, merge; later set balance and remittances) POST to preview routes
that render `admin/confirm.html`; the confirm form posts here. Enforcement is the `require_stepup`
dependency (signed payload, one-time nonce, open step-up window or fresh TOTP/recovery code), not the
template. See `app/services/stepup.py` for the flow and for how to register a new action.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.db import write_session
from app.services import stepup
from app.services.errors import ServiceError
from app.web import admin_deps as ad
from app.web.deps import client_ip
from app.web.middleware import no_store

router = APIRouter(route_class=ad.StepupRoute)


@router.post("/stepup/confirm", dependencies=[Depends(ad.require_admin_csrf)])
def confirm(request: Request, grant: stepup.StepupGrant = Depends(ad.require_stepup)):
    ip = client_ip(request)
    try:
        # One transaction: nonce consumption, the action and its audit entries commit together.
        with write_session() as db:
            result = stepup.run(db, grant, ip=ip)
    except stepup.AlreadyExecuted as exc:
        return no_store(ad.back(exc.back_path, msg="already_executed"))
    except ServiceError as exc:  # nothing was written (the nonce stays unspent): show it on the entry page
        return ad.back(grant.action.back_path(grant.params), err=ad.error_key(exc))
    return no_store(ad.back(result.path, msg=result.flash))
