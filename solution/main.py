import os
import uuid
import datetime
import json
import random
import string

import psycopg2
import redis
import uvicorn
import requests

from psycopg2.extras import RealDictCursor
from passlib.hash import bcrypt
from jose import jwt, JWTError

from fastapi import FastAPI, Request, Body, Header, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware



HTTP_ADDR = os.getenv("HTTP_ADDR", "0.0.0.0:8080")
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DATABASE", "postgres")
DB_USER = os.getenv("POSTGRES_USERNAME", "postgres")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "postgres")

REDIS_CONN_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_CONN_PORT = os.getenv("REDIS_PORT", "6379")

ANTI_FRAUD_HOST = os.getenv("ANTIFRAUD_ADDRESS", "localhost:9090")

JWT_RANDOM_SECRET = os.getenv(
    "JWT_RANDOM_SECRET",
    "THIS_IS_A_RANDOM_SECRET_" + "".join(random.choices(string.ascii_letters + string.digits, k=32))
)
JWT_SIGN_ALGO = "HS256"



app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)




def connect_pg():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )



def init_tables():
    c = connect_pg()
    m = c.cursor()
    m.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id UUID PRIMARY KEY,
            email VARCHAR(120) UNIQUE NOT NULL,
            pass_hash VARCHAR(200) NOT NULL,
            name VARCHAR(100) NOT NULL,
            surname VARCHAR(120),
            user_type VARCHAR(20) NOT NULL,
            avatar_url VARCHAR(350),
            age INT,
            country VARCHAR(20),
            categories TEXT,
            token_version INT NOT NULL DEFAULT 0
        )
        """
    )
    m.execute(
        """
        CREATE TABLE IF NOT EXISTS promos (
            id UUID PRIMARY KEY,
            company_id UUID NOT NULL,
            mode VARCHAR(10) NOT NULL,
            promo_common VARCHAR(30),
            promo_unique TEXT,
            description VARCHAR(300) NOT NULL,
            image_url VARCHAR(350),
            active_from DATE,
            active_until DATE,
            target_age_from INT,
            target_age_until INT,
            target_country VARCHAR(20),
            target_categories TEXT,
            max_count BIGINT,
            used_count BIGINT DEFAULT 0,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        )
        """
    )
    m.execute(
        """
        CREATE TABLE IF NOT EXISTS promo_likes (
            id SERIAL PRIMARY KEY,
            promo_id UUID NOT NULL,
            user_id UUID NOT NULL,
            UNIQUE(promo_id, user_id)
        )
        """
    )
    m.execute(
        """
        CREATE TABLE IF NOT EXISTS promo_comments (
            id UUID PRIMARY KEY,
            promo_id UUID NOT NULL,
            user_id UUID NOT NULL,
            text VARCHAR(1000) NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMP,
            deleted BOOLEAN NOT NULL DEFAULT FALSE
        )
        """
    )
    m.execute(
        """
        CREATE TABLE IF NOT EXISTS promo_activations (
            id UUID PRIMARY KEY,
            promo_id UUID NOT NULL,
            user_id UUID NOT NULL,
            activated_at TIMESTAMP NOT NULL DEFAULT NOW(),
            code_value VARCHAR(30)
        )
        """
    )
    c.commit()
    m.close()
    c.close()


init_tables()


redis_conn = redis.Redis(
    host=REDIS_CONN_HOST,
    port=int(REDIS_CONN_PORT),
    db=0
)


def make_uuid() -> str:
    return str(uuid.uuid4())

def pass_hash(p: str) -> str:
    return bcrypt.hash(p)

def passverify(p: str, h: str) -> bool:
    return bcrypt.verify(p, h)

def encode_jwt(uid: str, utype: str, ver: int):
    pl = {
        "sub": uid,
        "tp": utype,
        "ver": ver,
        "iat": int(datetime.datetime.utcnow().timestamp())
    }
    return jwt.encode(pl, JWT_RANDOM_SECRET, algorithm=JWT_SIGN_ALGO)

def decode_jwt(token: str):
    try:
        data = jwt.decode(token, JWT_RANDOM_SECRET, algorithms=[JWT_SIGN_ALGO])
        return data
    except JWTError:
        return None

def read_json_arr(s: str):
    if not s:
        return []
    try:
        return json.loads(s)
    except:
        return []

def check_password_rules(passw: str) -> bool:
    return 8 <= len(passw) <= 60

def get_promo_likes(pid: str) -> int:
    cn = connect_pg()
    cu = cn.cursor()
    cu.execute("SELECT COUNT(*) FROM promo_likes WHERE promo_id=%s", (pid,))
    res = cu.fetchone()[0]
    cu.close()
    cn.close()
    return res

def is_liked(pid: str, uid: str) -> bool:
    cn = connect_pg()
    cu = cn.cursor()
    cu.execute("SELECT 1 FROM promo_likes WHERE promo_id=%s AND user_id=%s", (pid, uid))
    r = cu.fetchone()
    cu.close()
    cn.close()
    return bool(r)

def is_activated(pid: str, uid: str) -> bool:
    cn = connect_pg()
    cu = cn.cursor()
    cu.execute("SELECT 1 FROM promo_activations WHERE promo_id=%s AND user_id=%s", (pid, uid))
    r = cu.fetchone()
    cu.close()
    cn.close()

    return bool(r)


def get_company_name(cid: str) -> str:
    cn = connect_pg()
    cu = cn.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT name FROM accounts WHERE id=%s", (cid,))
    row = cu.fetchone()

    cu.close()
    cn.close()
    if row:
        return row["name"]
    return "Unknown"


# def promo_comments_count(pid: str) -> int:
#   cn = connect_pg()
#   cu = cn.cursor()
#   cu.execute(SELECT COUNT(*) FROM promo_comments WHERE promo_id=" + pid + " AND deleted=false")
#   c = cu.fetchone()[0]
#   cn.close()
#   return c


def promo_comments_count(pid: str) -> int:
    cn = connect_pg()
    cu = cn.cursor()
    cu.execute("SELECT COUNT(*) FROM promo_comments WHERE promo_id=%s AND deleted=false", (pid,))
    c = cu.fetchone()[0]
    cu.close()

    cn.close()
    return c

def check_promo_exists(pid: str):
    cn = connect_pg()
    cu = cn.cursor()
    cu.execute("SELECT 1 FROM promos WHERE id=%s", (pid,))
    r = cu.fetchone()
    cu.close()
    cn.close()
    if not r:
        raise HTTPException(status_code=404, detail="Промокод не найден")


def assemble_for_user(row_data, user_id: str):
    c_name = get_company_name(row_data["company_id"])
    return {
        "promo_id": str(row_data["id"]),
        "company_id": str(row_data["company_id"]),
        "company_name": c_name,
        "description": row_data["description"],
        "image_url": row_data["image_url"],
        "active": bool(row_data["active"]),
        "is_activated_by_user": is_activated(row_data["id"], user_id),
        "like_count": get_promo_likes(row_data["id"]),
        "is_liked_by_user": is_liked(row_data["id"], user_id),
        "comment_count": promo_comments_count(row_data["id"])
    }

def get_user_data(uid: str):
    cn = connect_pg()
    cu = cn.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT name,surname,avatar_url FROM accounts WHERE id=%s", (uid,))
    row = cu.fetchone()
    cu.close()
    cn.close()
    return row if row else {"name": "?", "surname": "?", "avatar_url": None}

def build_comment(comment_id: str):
    cn = connect_pg()
    cu = cn.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM promo_comments WHERE id=%s", (comment_id,))
    row = cu.fetchone()
    cu.close()
    cn.close()

    if not row or row["deleted"]:
        raise HTTPException(status_code=404, detail="Комментарий не существует")

    user_info = get_user_data(row["user_id"])
    dt = row["updated_at"] or row["created_at"]
    return {
        "id": str(row["id"]),
        "text": row["text"],
        "date": dt.isoformat(),
        "author": {
            "name": user_info["name"],
            "surname": user_info["surname"],
            "avatar_url": user_info["avatar_url"]
        }
    }

def current_account(authorization: str = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Не авторизован")
    token_data = decode_jwt(authorization[7:].strip())

    if not token_data:
        raise HTTPException(status_code=401, detail="Не авторизован")

    sub = token_data.get("sub")
    tp = token_data.get("tp")
    v = token_data.get("ver")

    if not sub or not tp or v is None:
        raise HTTPException(status_code=401, detail="Не авторизован")

    cpg = connect_pg()
    curs = cpg.cursor(cursor_factory=RealDictCursor)

    curs.execute("SELECT * FROM accounts WHERE id=%s", (sub,))
    row = curs.fetchone()
    curs.close()
    cpg.close()
    if not row or row["token_version"] != v:
        raise HTTPException(status_code=401, detail="Не авторизован")
    return row


@app.get("/api/ping")

def handle_ping():
    return {"status": "PROOOD"}


@app.post("/api/business/auth/sign-up")

def bus_signup(payload: dict = Body(...)):
    em = payload.get("email")
    pwd = payload.get("password")
    nm = payload.get("name")

    if not (em and pwd and nm):
        raise HTTPException(400, "Некорректные данные")

    em_l = em.strip().lower()
    if not check_password_rules(pwd):
        raise HTTPException(400, "Пароль не удовлетворяет требованиям")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM accounts WHERE email=%s", (em_l,))
    conflict = cu.fetchone()
    if conflict:
        cu.close()
        cpg.close()
        raise HTTPException(409, "Такой email уже зарегистрирован")

    aid = make_uuid()
    phash = pass_hash(pwd)
    cu.execute(
        """INSERT INTO accounts(id, email, pass_hash, name, user_type, token_version)
           VALUES (%s, %s, %s, %s, 'company', 0)""",
        (aid, em_l, phash, nm.strip())
    )
    cpg.commit()
    token = encode_jwt(aid, "company", 0)
    cu.close()
    cpg.close()
    return {"token": token, "company_id": aid}


@app.post("/api/business/auth/sign-in")

def bus_signin(payload: dict = Body(...)):
    em = payload.get("email")
    pwd = payload.get("password")
    if not em or not pwd:
        raise HTTPException(400, "Некорректные данные")

    e_l = em.strip().lower()
    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM accounts WHERE email=%s AND user_type='company'", (e_l,))
    row = cu.fetchone()
    if not row:
        cu.close()
        cpg.close()
        raise HTTPException(401, "Неверный email или пароль")

    if not passverify(pwd, row["pass_hash"]):
        cu.close()
        cpg.close()
        raise HTTPException(401, "Неверный email или пароль")

    new_version = (row["token_version"] or 0) + 1
    cu.execute("UPDATE accounts SET token_version=%s WHERE id=%s", (new_version, row["id"]))
    cpg.commit()
    cu.close()
    cpg.close()

    token = encode_jwt(str(row["id"]), "company", new_version)
    return {"token": token}



@app.post("/api/business/promo", status_code=201)

def create_business_promo(body: dict = Body(...), acc=Depends(current_account)):
    if acc["user_type"] != "company":
        raise HTTPException(401, "Неа доступа")

    mode = body.get("mode")
    if mode not in ("COMMON", "UNIQUE"):
        raise HTTPException(400, "mode must be COMMON or UNIQUE")

    desc = body.get("description")
    if not isinstance(desc, str) or len(desc) < 10:
        raise HTTPException(400, "Invalid description")

    max_count = body.get("max_count")
    if not isinstance(max_count, int):
        raise HTTPException(400, "max_count обязателен")

    pr_common = body.get("promo_common")
    pr_unique = body.get("promo_unique")

    if mode == "COMMON":
        if not isinstance(pr_common, str):
            raise HTTPException(400, "promo_common нужен для COMMON")
        if pr_unique is not None:
            raise HTTPException(400, "promo_unique не используется в COMMON")
        pr_common_val = pr_common
        pr_unique_val = None
    else:
        if not isinstance(pr_unique, list):
            raise HTTPException(400, "promo_unique нужен для UNIQUE")
        if pr_common is not None:
            raise HTTPException(400, "promo_common не используется в UNIQUE")
        pr_common_val = None
        pr_unique_val = json.dumps(pr_unique)

    target_data = body.get("target", {})
    age_from = target_data.get("age_from")
    age_to = target_data.get("age_until")
    t_country = target_data.get("country")
    t_cats = target_data.get("categories")
    t_cats_str = json.dumps(t_cats) if isinstance(t_cats, list) else None

    af = body.get("active_from")
    au = body.get("active_until")
    img = body.get("image_url")

    pid = make_uuid()
    cpg = connect_pg()
    cu = cpg.cursor()
    cu.execute(
        """
        INSERT INTO promos(
            id, company_id, mode, promo_common, promo_unique,
            description, image_url, active_from, active_until,
            target_age_from, target_age_until, target_country, target_categories,
            max_count
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            pid, acc["id"], mode,
            pr_common_val, pr_unique_val,
            desc, img,
            af, au,
            age_from, age_to,
            t_country, t_cats_str,
            max_count
        )
    )
    cpg.commit()
    cu.close()
    cpg.close()
    return {"id": pid}


@app.get("/api/business/promo")

def list_company_promos(
    limit: int = 10,
    offset: int = 0,
    sort_by: str = None,
    country: list[str] = None,
    acc=Depends(current_account)
):
    if acc["user_type"] != "company":
        raise HTTPException(401, "Нет доступа")

    base_query = "SELECT * FROM promos WHERE company_id=%s"
    params = [acc["id"]]
    wheres = []
    order_sql = "ORDER BY created_at DESC"
    if sort_by == "active_from":
        order_sql = "ORDER BY active_from DESC NULLS LAST"
    elif sort_by == "active_until":
        order_sql = "ORDER BY active_until DESC NULLS LAST"

    if country:
        wheres.append("(target_country IS NULL OR LOWER(target_country)=ANY(%s))")

        cs = set()
        for ct in country:
            if "," in ct:
                for piece in ct.split(","):
                    cs.add(piece.strip().lower())
            else:
                cs.add(ct.strip().lower())
        params.append(list(cs))

    if wheres:
        base_query += " AND " + " AND ".join(wheres)

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)

    count_query = f"SELECT COUNT(*) as cnt FROM promos WHERE company_id=%s"
    if wheres:
        count_query += " AND " + " AND ".join(wheres)

    cu.execute(count_query, tuple(params))
    total = cu.fetchone()["cnt"]

    final_query = f"{base_query} {order_sql} LIMIT {limit} OFFSET {offset}"
    cu.execute(final_query, tuple(params))
    rows = cu.fetchall()

    cu.close()
    cpg.close()

    data_out = []
    for r in rows:
        item = {
            "promo_id": str(r["id"]),
            "company_id": str(r["company_id"]),
            "company_name": acc["name"],
            "description": r["description"],
            "image_url": r["image_url"],
            "mode": r["mode"],
            "promo_common": r["promo_common"],
            "promo_unique": read_json_arr(r["promo_unique"]),
            "max_count": r["max_count"],
            "used_count": r["used_count"],
            "active_from": r["active_from"].isoformat() if r["active_from"] else None,
            "active_until": r["active_until"].isoformat() if r["active_until"] else None,
            "like_count": get_promo_likes(r["id"]),
            "active": bool(r["active"]),
            "target": {
                "age_from": r["target_age_from"],
                "age_until": r["target_age_until"],
                "country": r["target_country"],
                "categories": read_json_arr(r["target_categories"])
            }
        }
        data_out.append(item)

    return JSONResponse(
        content=data_out,
        headers={"X-Total-Count": str(total)}
    )


@app.get("/api/business/promo/{promo_id}")
def get_company_promo(promo_id: str, acc=Depends(current_account)):
    if acc["user_type"] != "company":
        raise HTTPException(401, "Нет доступа")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM promos WHERE id=%s", (promo_id,))
    row = cu.fetchone()
    if not row:
        cu.close()
        cpg.close()
        raise HTTPException(404, "Не найдено")
    if str(row["company_id"]) != str(acc["id"]):
        cu.close()
        cpg.close()
        raise HTTPException(403, "Чужой промокод")

    out = {
        "promo_id": str(row["id"]),
        "company_id": str(row["company_id"]),
        "company_name": acc["name"],
        "description": row["description"],
        "image_url": row["image_url"],
        "mode": row["mode"],
        "promo_common": row["promo_common"],
        "promo_unique": read_json_arr(row["promo_unique"]),
        "max_count": row["max_count"],
        "used_count": row["used_count"],
        "active": bool(row["active"]),
        "like_count": get_promo_likes(row["id"]),
        "target": {
            "age_from": row["target_age_from"],
            "age_until": row["target_age_until"],
            "country": row["target_country"],
            "categories": read_json_arr(row["target_categories"])
        },
        "active_from": row["active_from"].isoformat() if row["active_from"] else None,
        "active_until": row["active_until"].isoformat() if row["active_until"] else None
    }
    cu.close()
    cpg.close()
    return out


@app.patch("/api/business/promo/{promo_id}")
def patch_company_promo(promo_id: str, body: dict = Body(...), acc=Depends(current_account)):
    if acc["user_type"] != "company":
        raise HTTPException(401, "Нет доступа")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM promos WHERE id=%s", (promo_id,))
    existing = cu.fetchone()
    if not existing:
        cu.close()
        cpg.close()
        raise HTTPException(404, "Не найдено")
    if str(existing["company_id"]) != str(acc["id"]):
        cu.close()
        cpg.close()
        raise HTTPException(403, "Чужой промокод")

    dsc = body.get("description", existing["description"])
    img = body.get("image_url", existing["image_url"])
    af = body.get("active_from", existing["active_from"])
    au = body.get("active_until", existing["active_until"])
    new_mc = body.get("max_count", existing["max_count"])

    target_info = body.get("target")
    if target_info and isinstance(target_info, dict):
        new_age_f = target_info.get("age_from", existing["target_age_from"])
        new_age_u = target_info.get("age_until", existing["target_age_until"])
        new_t_country = target_info.get("country", existing["target_country"])
        new_t_cats = target_info.get("categories", read_json_arr(existing["target_categories"]))
    else:
        new_age_f = existing["target_age_from"]
        new_age_u = existing["target_age_until"]
        new_t_country = existing["target_country"]
        new_t_cats = read_json_arr(existing["target_categories"])

    used_c = existing["used_count"] or 0
    if existing["mode"] == "COMMON":
        if used_c > new_mc:
            cu.close()
            cpg.close()
            raise HTTPException(400, "max_count ниже уже использованных")
    else:
        if new_mc != 1:
            cu.close()
            cpg.close()
            raise HTTPException(400, "max_count должен быть 1 для UNIQUE")
        new_mc = 1

    nowd = datetime.date.today()
    if isinstance(af, str):
        af = datetime.datetime.strptime(af, "%Y-%m-%d").date()
    if isinstance(au, str):
        au = datetime.datetime.strptime(au, "%Y-%m-%d").date()

    new_active = True
    if used_c >= new_mc:
        new_active = False
    if af and nowd < af:
        new_active = False
    if au and nowd > au:
        new_active = False

    if existing["mode"] == "COMMON" and new_mc > used_c:
        if af and nowd < af:
            new_active = False
        if au and nowd > au:
            new_active = False
        if new_active is not False:
            new_active = True

    jcats = json.dumps(new_t_cats)

    cu.execute(
        """
        UPDATE promos
        SET
            description=%s,
            image_url=%s,
            active_from=%s,
            active_until=%s,
            max_count=%s,
            target_age_from=%s,
            target_age_until=%s,
            target_country=%s,
            target_categories=%s,
            active=%s
        WHERE id=%s
        RETURNING *
        """,
        (
            dsc, img, af, au, new_mc,
            new_age_f, new_age_u, new_t_country,
            jcats, new_active,
            promo_id
        )
    )
    fresh = cu.fetchone()
    cpg.commit()
    cu.close()
    cpg.close()

    res = {
        "promo_id": str(fresh["id"]),
        "company_id": str(fresh["company_id"]),
        "company_name": acc["name"],
        "description": fresh["description"],
        "image_url": fresh["image_url"],
        "mode": fresh["mode"],
        "promo_common": fresh["promo_common"],
        "promo_unique": read_json_arr(fresh["promo_unique"]),
        "max_count": fresh["max_count"],
        "used_count": fresh["used_count"],
        "active": bool(fresh["active"]),
        "like_count": get_promo_likes(fresh["id"]),
        "target": {
            "age_from": fresh["target_age_from"],
            "age_until": fresh["target_age_until"],
            "country": fresh["target_country"],
            "categories": read_json_arr(fresh["target_categories"])
        },
        "active_from": fresh["active_from"].isoformat() if fresh["active_from"] else None,
        "active_until": fresh["active_until"].isoformat() if fresh["active_until"] else None
    }
    return res


@app.get("/api/business/promo/{promo_id}/stat")      #/api/business/promo/{promo_id}/stat
def get_business_promo_stat(promo_id: str, acc=Depends(current_account)):
    if acc["user_type"] != "company":
        raise HTTPException(401, "Нет доступа")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM promos WHERE id=%s", (promo_id,))   #cu.execute("SELECT * FROM promos WHERE id=" + promo_id)
    pinfo = cu.fetchone()
    if not pinfo:
        cu.close()
        cpg.close()
        raise HTTPException(404, "Не найдено")
    if str(pinfo["company_id"]) != str(acc["id"]):
        cu.close()
        cpg.close()
        raise HTTPException(403, "Чужой промокод")

    cu.execute("SELECT COUNT(*) as cnt FROM promo_activations WHERE promo_id=%s", (promo_id,))
    total = cu.fetchone()["cnt"]

    cu.execute(
        """
        SELECT LOWER(a.country) as c, COUNT(pa.id) as cnt
        FROM promo_activations pa
        JOIN accounts a ON pa.user_id=a.id
        WHERE pa.promo_id=%s
        GROUP BY LOWER(a.country)
        """,
        (promo_id,)
    )
    rows = cu.fetchall()
    cu.close()
    cpg.close()

    filtered = [x for x in rows if x["c"]]
    filtered.sort(key=lambda x: x["c"])
    arr = []
    for x in filtered:
        arr.append({
            "country": x["c"],
            "activations_count": x["cnt"]
        })
    return {
        "activations_count": total,
        "countries": arr
    }


@app.post("/api/user/auth/sign-up")

def user_signup(body: dict = Body(...)):
    mail = body.get("email")
    passwd = body.get("password")
    if not mail or not passwd:
        raise HTTPException(400, "Некорректные данные")

    ml = mail.strip().lower()
    if not check_password_rules(passwd):
        raise HTTPException(400, "Пароль не удовлетворяет требованиям")

    nm = body.get("name")
    sn = body.get("surname")
    if not nm or not sn:
        raise HTTPException(400, "Некорректные данные (name, surname)")

    av = body.get("avatar_url")
    other = body.get("other", {})
    ag = other.get("age")
    ctr = other.get("country")
    cats = other.get("categories", [])

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM accounts WHERE email=%s AND user_type='user'", (ml,))
    ex = cu.fetchone()
    if ex:
        cu.close()
        cpg.close()
        raise HTTPException(409, "Такой email уже зарегистрирован")

    uid = make_uuid()
    hashed = pass_hash(passwd)
    cts = json.dumps(cats) if isinstance(cats, list) else None

    cu.execute(
        """
        INSERT INTO accounts(
            id, email, pass_hash, name, surname, user_type,
            avatar_url, age, country, categories, token_version
        )
        VALUES(%s,%s,%s,%s,%s,'user',%s,%s,%s,%s,0)
        """,
        (uid, ml, hashed, nm, sn, av, ag, ctr, cts)
    )
    cpg.commit()
    cu.close()
    cpg.close()

    token = encode_jwt(uid, "user", 0)
    return {"token": token}


@app.post("/api/user/auth/sign-in")
def user_signin(body: dict = Body(...)):
    mail = body.get("email")
    pasw = body.get("password")
    if not mail or not pasw:
        raise HTTPException(400, "Некорректные данные")
    ml = mail.strip().lower()

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM accounts WHERE email=%s AND user_type='user'", (ml,))
    user_row = cu.fetchone()
    if not user_row:
        cu.close()
        cpg.close()
        raise HTTPException(401, "Неверный email или пароль")

    if not passverify(pasw, user_row["pass_hash"]):
        cu.close()
        cpg.close()
        raise HTTPException(401, "Неверный email или пароль")

    new_ver = (user_row["token_version"] or 0) + 1
    cu.execute("UPDATE accounts SET token_version=%s WHERE id=%s", (new_ver, user_row["id"]))
    cpg.commit()
    cu.close()
    cpg.close()

    token = encode_jwt(str(user_row["id"]), "user", new_ver)
    return {"token": token}



@app.get("/api/user/profile")
def get_profile(acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    cat_arr = read_json_arr(acc["categories"])
    return {
        "name": acc["name"],
        "surname": acc["surname"],
        "email": acc["email"],
        "avatar_url": acc["avatar_url"],
        "other": {
            "age": acc["age"],
            "country": acc["country"],
            "categories": cat_arr
        }
    }


@app.patch("/api/user/profile")
def update_profile(body: dict = Body(...), acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Неа доступа")

    new_n = body.get("name", acc["name"])
    new_s = body.get("surname", acc["surname"])
    new_av = body.get("avatar_url", acc["avatar_url"])
    new_p = body.get("password")

    phash = None
    if new_p is not None:
        if not check_password_rules(new_p):
            raise HTTPException(400, "Пароль неправильный")
        phash = pass_hash(new_p)

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)

    sql = "UPDATE accounts SET name=%s, surname=%s, avatar_url=%s"
    params = [new_n, new_s, new_av]
    if phash:
        sql += ", pass_hash=%s"
        params.append(phash)
    sql += " WHERE id=%s RETURNING *"
    params.append(acc["id"])

    cu.execute(sql, tuple(params))
    row = cu.fetchone()
    cpg.commit()
    cu.close()
    cpg.close()

    cat_arr = read_json_arr(row["categories"])
    return {
        "name": row["name"],
        "surname": row["surname"],
        "email": row["email"],
        "avatar_url": row["avatar_url"],
        "other": {
            "age": row["age"],
            "country": row["country"],
            "categories": cat_arr
        }
    }



@app.get("/api/user/feed")
def user_feed_view(
    limit: int = 10,
    offset: int = 0,
    category: str = None,
    active: bool = None,
    acc=Depends(current_account)
):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")



    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    q = "SELECT * FROM promos WHERE 1=1"
    wh = []
    pr = []

    if active is not None:
        wh.append("active=%s")
        pr.append(active)
    if category:
        wh.append("LOWER(target_categories)::text LIKE %s")
        cat_search = f'%"{category.strip().lower()}"%'
        pr.append(cat_search)

    if wh:
        q += " AND " + " AND ".join(wh)

    order_clause = " ORDER BY created_at DESC"
    lo_clause = f" LIMIT {limit} OFFSET {offset}"
    count_sql = f"SELECT COUNT(*) as cnt FROM ({q}) as sub"
    cu.execute(count_sql, tuple(pr))
    total = cu.fetchone()["cnt"]

    final_sql = q + order_clause + lo_clause
    cu.execute(final_sql, tuple(pr))
    rows = cu.fetchall()
    cu.close()
    cpg.close()

    result = []
    for r in rows:
        result.append(assemble_for_user(r, acc["id"]))
    return JSONResponse(content=result, headers={"X-Total-Count": str(total)})

@app.get("/api/user/promo/{promo_id}")

def get_promo_for_user(promo_id: str, acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM promos WHERE id=%s", (promo_id,))
    row = cu.fetchone()
    cu.close()
    cpg.close()

    if not row:
        raise HTTPException(404, "Не найдено")

    return assemble_for_user(row, acc["id"])


@app.post("/api/user/promo/{promo_id}/like")
def like_promo(promo_id: str, acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    check_promo_exists(promo_id)
    cpg = connect_pg()
    cu = cpg.cursor()
    cu.execute(
        "INSERT INTO promo_likes(promo_id,user_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",
        (promo_id, acc["id"])
    )
    cpg.commit()
    cu.close()
    cpg.close()
    return {"status": "ok"}


@app.delete("/api/user/promo/{promo_id}/like")
def unlike_promo(promo_id: str, acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    check_promo_exists(promo_id)
    cpg = connect_pg()
    cu = cpg.cursor()
    cu.execute("DELETE FROM promo_likes WHERE promo_id=%s AND user_id=%s", (promo_id, acc["id"]))
    cpg.commit()
    cu.close()
    cpg.close()
    return {"status": "ok"}



@app.post("/api/user/promo/{promo_id}/comments", status_code=201)
def add_comment_to_promo(promo_id: str, body: dict = Body(...), acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    check_promo_exists(promo_id)
    txt = body.get("text")
    if not txt or len(txt) < 10 or len(txt) > 1000:
        raise HTTPException(400, "Неверный текст")

    cm_id = make_uuid()
    cpg = connect_pg()
    cu = cpg.cursor()
    cu.execute(
        "INSERT INTO promo_comments(id, promo_id, user_id, text) VALUES(%s,%s,%s,%s)",
        (cm_id, promo_id, acc["id"], txt)
    )
    cpg.commit()
    cu.close()
    cpg.close()
    return build_comment(cm_id)


@app.get("/api/user/promo/{promo_id}/comments")
def get_promo_comments(
    promo_id: str,
    limit: int = 10,
    offset: int = 0,
    acc=Depends(current_account)
):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    check_promo_exists(promo_id)
    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT COUNT(*) as cnt FROM promo_comments WHERE promo_id=%s AND deleted=false", (promo_id,))
    total = cu.fetchone()["cnt"]
    cu.execute(
        """
        SELECT id FROM promo_comments
        WHERE promo_id=%s AND deleted=false
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
        """,
        (promo_id, limit, offset)
    )
    rows = cu.fetchall()
    cu.close()
    cpg.close()

    result = []
    for r in rows:
        result.append(build_comment(r["id"]))
    return JSONResponse(content=result, headers={"X-Total-Count": str(total)})


@app.get("/api/user/promo/{promo_id}/comments/{comment_id}")
def get_one_comment(promo_id: str, comment_id: str, acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    check_promo_exists(promo_id)
    cpg = connect_pg()
    cu = cpg.cursor()
    cu.execute("SELECT 1 FROM promo_comments WHERE id=%s AND promo_id=%s AND deleted=false", (comment_id, promo_id))
    row = cu.fetchone()
    cu.close()
    cpg.close()
    if not row:
        raise HTTPException(404, "Комментарий или промокод не найден")
    return build_comment(comment_id)


@app.put("/api/user/promo/{promo_id}/comments/{comment_id}")
def edit_comment(promo_id: str, comment_id: str, body: dict = Body(...), acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    new_txt = body.get("text")
    if not new_txt or len(new_txt) < 10 or len(new_txt) > 1000:
        raise HTTPException(400, "Неверный текст")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM promo_comments WHERE id=%s AND promo_id=%s AND deleted=false", (comment_id, promo_id))
    row = cu.fetchone()
    if not row:
        cu.close()
        cpg.close()
        raise HTTPException(404, "Комментарий не найден")
    if str(row["user_id"]) != str(acc["id"]):
        cu.close()
        cpg.close()
        raise HTTPException(403, "Чужой комментарий")

    cu.execute("UPDATE promo_comments SET text=%s, updated_at=NOW() WHERE id=%s", (new_txt, comment_id))
    cpg.commit()
    cu.close()
    cpg.close()
    return build_comment(comment_id)


@app.delete("/api/user/promo/{promo_id}/comments/{comment_id}")
def delete_comment(promo_id: str, comment_id: str, acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM promo_comments WHERE id=%s AND promo_id=%s AND deleted=false", (comment_id, promo_id))
    row = cu.fetchone()
    if not row:
        cu.close()
        cpg.close()
        raise HTTPException(404, "Комментарий не найден")
    if str(row["user_id"]) != str(acc["id"]):
        cu.close()
        cpg.close()
        raise HTTPException(403, "Чужой комментарий")

    cu.execute("UPDATE promo_comments SET deleted=true WHERE id=%s", (comment_id,))
    cpg.commit()
    cu.close()
    cpg.close()
    return {"status": "ok"}


@app.post("/api/user/promo/{promo_id}/activate")
def activate_code(promo_id: str, acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT * FROM promos WHERE id=%s", (promo_id,))
    promo = cu.fetchone()
    if not promo:
        cu.close()
        cpg.close()
        raise HTTPException(404, "Не найдено")

    if not promo["active"]:
        cu.close()
        cpg.close()
        raise HTTPException(403, "Промокод неактивен")

    user_age = acc["age"]
    user_ctr = acc["country"]
    af = promo["target_age_from"]
    au = promo["target_age_until"]
    if af is not None and user_age is not None and user_age < af:
        cu.close()
        cpg.close()
        raise HTTPException(403, "Возраст не подходит")
    if au is not None and user_age is not None and user_age > au:
        cu.close()
        cpg.close()
        raise HTTPException(403, "Возраст не подходит")

    if promo["target_country"] and user_ctr:
        if user_ctr.strip().lower() != promo["target_country"].strip().lower():
            cu.close()
            cpg.close()
            raise HTTPException(403, "Страна не подходит")

    nowd = datetime.date.today()
    if promo["active_from"] and nowd < promo["active_from"]:
        cu.close()
        cpg.close()
        raise HTTPException(403, "Пока недоступно")
    if promo["active_until"] and nowd > promo["active_until"]:
        cu.close()
        cpg.close()
        raise HTTPException(403, "Срок истёк")

    email_lower = acc["email"].strip().lower()
    cache_key = f"antifraud:{email_lower}"
    cached_raw = redis_conn.get(cache_key)
    need_to_call = True

    if cached_raw:
        try:
            obj = json.loads(cached_raw)
            cache_until = obj.get("cache_until")
            is_ok = obj.get("ok", True)
            if cache_until:
                c_until_dt = datetime.datetime.fromisoformat(cache_until)
                if datetime.datetime.utcnow() < c_until_dt:
                    need_to_call = False
                    if not is_ok:
                        cu.close()
                        cpg.close()
                        raise HTTPException(403, "Антифрод не пройден")
        except:
            pass

    if need_to_call:
        body = {
            "user_email": acc["email"],
            "promo_id": promo_id
        }
        done = False
        for _ in range(2):
            try:
                url = f"http://{ANTI_FRAUD_HOST}/api/validate"

                r = requests.post(url, json=body, headers={"Content-Type": "application/json"}, timeout=3)
                if r.status_code == 200:
                    resp_json = r.json()
                    antif_ok = resp_json.get("ok", True)
                    c_u = resp_json.get("cache_until")
                    store_obj = {"ok": antif_ok}
                    if c_u:
                        store_obj["cache_until"] = c_u
                    redis_conn.set(cache_key, json.dumps(store_obj))
                    if not antif_ok:
                        cu.close()
                        cpg.close()
                        raise HTTPException(403, "Антифрод не пройден")
                    done = True
                    break
            except:
                pass
        if not done:
            cu.close()
            cpg.close()
            raise HTTPException(403, "Антифрод сервис недоступен")

    if promo["mode"] == "COMMON":
        code_val = promo["promo_common"]
    else:
        all_codes = read_json_arr(promo["promo_unique"])
        cu.execute("SELECT code_value FROM promo_activations WHERE promo_id=%s", (promo_id,))
        used = cu.fetchall()
        usedset = {u["code_value"] for u in used if u["code_value"]}
        free_codes = [c for c in all_codes if c not in usedset]
        if not free_codes:
            cu.close()
            cpg.close()
            raise HTTPException(403, "Все уникальные коды исчерпаны")
        code_val = free_codes[0]

    act_id = make_uuid()
    cu.execute(
        "INSERT INTO promo_activations(id,promo_id,user_id,code_value) VALUES(%s,%s,%s,%s)",
        (act_id, promo_id, acc["id"], code_val)
    )
    new_used = (promo["used_count"] or 0) + 1
    cu.execute("UPDATE promos SET used_count=%s WHERE id=%s", (new_used, promo_id))

    if promo["mode"] == "COMMON":
        if new_used >= promo["max_count"]:
            cu.execute("UPDATE promos SET active=false WHERE id=%s", (promo_id,))
    else:
        if len(all_codes) == new_used:
            cu.execute("UPDATE promos SET active=false WHERE id=%s", (promo_id,))

    cpg.commit()
    cu.close()
    cpg.close()
    return {"promo": code_val}


@app.get("/api/user/promo/history")
def get_user_history(limit: int=10, offset: int=0, acc=Depends(current_account)):
    if acc["user_type"] != "user":
        raise HTTPException(401, "Нет доступа")

    cpg = connect_pg()
    cu = cpg.cursor(cursor_factory=RealDictCursor)
    cu.execute("SELECT COUNT(*) as cnt FROM promo_activations WHERE user_id=%s", (acc["id"],))
    tot = cu.fetchone()["cnt"]

    cu.execute(
        """
        SELECT promos.*, promo_activations.activated_at as act_time
        FROM promo_activations
        JOIN promos ON promo_activations.promo_id=promos.id
        WHERE promo_activations.user_id=%s
        ORDER BY promo_activations.activated_at DESC
        LIMIT %s OFFSET %s
        """,
        (acc["id"], limit, offset)
    )
    rows = cu.fetchall()
    cu.close()
    cpg.close()

    arr = []
    for r in rows:
        arr.append(assemble_for_user(r, acc["id"]))
    return JSONResponse(content=arr, headers={"X-Total-Count": str(tot)})





#uvicorn main:app --reload
#curl http://localhost:8080/api/ping

if __name__ == "__main__":
    host, port = "0.0.0.0", 8080
    env_addr = os.getenv("HTTP_ADDR")
    if env_addr and ":" in env_addr:
        splitted = env_addr.split(":")
        host = splitted[0]
        port = int(splitted[1])
    else:
        maybe_port = os.getenv("SERVER_PORT")
        if maybe_port:
            port = int(maybe_port)

    uvicorn.run(app, host=host, port=port)
