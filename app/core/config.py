from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    # Database
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "app"
    POSTGRES_USER: str = "appuser"
    POSTGRES_PASSWORD: str = "apppass"

    # JWT
    SECRET_KEY: str = "CHANGE_ME_SUPER_SECRET_KEY"            # access token
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_SECRET_KEY: str = "CHANGE_ME_REFRESH_SECRET_KEY"  # refresh token
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 30

    # URLs for building email links
    FRONTEND_BASE_URL: str = "http://localhost:3000"
    BACKEND_BASE_URL: str = "http://localhost:8000"

    # SMTP (prod); dev: None -> in-console
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_USE_TLS: bool = True
    EMAIL_FROM: str = "no-reply@example.com"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
