from fastapi import FastAPI, Request, Form, Response, Depends, HTTPException,UploadFile, File
from sqlalchemy.orm import Session
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi import Path
from fastapi.templating import Jinja2Templates
from models import Base, IoC, HashIoC, UrlIoC, DomainIoC
from database import DATABASE_URL, SessionLocal, get_specific_ioc_db, get_db
from modules.alienvault import get_ioc_data
from ioc_type.handle_ip import handle_ip
from ioc_type.handle_domain import handle_domain
from ioc_type.handle_hash import handle_hash
from ioc_type.handle_url import handle_url
import hashlib
from typing import Optional


app = FastAPI()
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "status": "Success"}
    )


@app.post("/search")
async def create_ioc(ioc: str = Form(...),file: Optional[UploadFile] = None):
    if file:
        contents = await file.read()
        hash_obj = hashlib.sha256(contents)
        ioc = hash_obj.hexdigest()

    if not ioc:
        return {"error": "Either provide IoC or upload a file for hashing."}

    ioc = ioc.strip()
    alien_vault_data = await get_ioc_data(ioc)
    ioc_type = alien_vault_data.get("type", "Unknown")

    existing_ioc = None
    match ioc_type:
        case "IPv4":
            existing_ioc = get_specific_ioc_db(ioc, IoC)
        case "hash":
            existing_ioc = get_specific_ioc_db(ioc, HashIoC)
        case "URL":
            existing_ioc = get_specific_ioc_db(ioc, UrlIoC)
        case "Domain":
            existing_ioc = get_specific_ioc_db(ioc, DomainIoC)

    if existing_ioc:
        return RedirectResponse(url=f"/search?status=exists&ioc={ioc}", status_code=303)

    else:
        match ioc_type:
            case "IPv4":
                status = await handle_ip(ioc)
            case "hash":
                status = await handle_hash(ioc)
            case "URL":
                status = await handle_url(ioc)
            case "Domain":
                status = await handle_domain(ioc)

        # return RedirectResponse(url=f"/search?status={status}", status_code=303)
        return RedirectResponse(
            url=f"/search?status={status}&ioc={ioc}", status_code=303
        )


async def get_specific_ioc(
    ioc_type: str, ioc: str = Path(...), db: Session = Depends(get_db)
):
    result = None

    match ioc_type:
        case "IPv4":
           result= db.query(IoC).filter(IoC.ioc == ioc).first()
        case "hash":
           result= db.query(HashIoC).filter(HashIoC.ioc == ioc).first()
        case "URL":
           result= db.query(UrlIoC).filter(UrlIoC.ioc == ioc).first()
        case "Domain":
           result= db.query(DomainIoC).filter(DomainIoC.ioc == ioc).first()
        case _:
            raise HTTPException(status_code=400, detail="Invalid IoC type.")
    return result

@app.get("/search", response_class=HTMLResponse)
async def search_form(
    request: Request, status: str = None, ioc: str = None, db: Session = Depends(get_db)
):
    ioc_record = None
    ioc_template = None

    if ioc:
        match ioc:
            case _ if db.query(IoC).filter(IoC.ioc == ioc).first():
                ioc_record = db.query(IoC).filter(IoC.ioc == ioc).first()
                ioc_template = "record_ipv4.html"
            case _ if db.query(HashIoC).filter(HashIoC.ioc == ioc).first():
                ioc_record = db.query(HashIoC).filter(HashIoC.ioc == ioc).first()
                ioc_template = "record_hash.html"
            case _ if db.query(UrlIoC).filter(UrlIoC.ioc == ioc).first():
                ioc_record = db.query(UrlIoC).filter(UrlIoC.ioc == ioc).first()
                ioc_template = "record_url.html"
            case _ if db.query(DomainIoC).filter(DomainIoC.ioc == ioc).first():
                ioc_record = db.query(DomainIoC).filter(DomainIoC.ioc == ioc).first()
                ioc_template = "record_domain.html"

    return templates.TemplateResponse(
        "search.html",
        {
            "request": request,
            "status": status,
            "ioc": ioc_record,
            "ioc_template": ioc_template,
        },
    )
