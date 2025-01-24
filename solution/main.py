import os
from fastapi import FastAPI
import uvicorn


SERVER_ADDRESS = os.getenv("SERVER_ADDRESS", "0.0.0.0:8080")

app = FastAPI()

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

@app.get("/api/ping")
def send():
    return {"status": "PROOOD"}

if __name__ == "__main__":
    host, port = "0.0.0.0", 8080
    addr = os.getenv("SERVER_ADDRESS")
    if addr and ":" in addr:
        splitted = addr.split(":")
        host = splitted[0]
        port = int(splitted[1])
    uvicorn.run(app, host=host, port=port)
