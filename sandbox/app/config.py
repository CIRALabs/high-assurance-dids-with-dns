import pathlib

from pydantic_settings import BaseSettings, SettingsConfigDict


from typing import List, Optional, Union

# Project Directories
ROOT = pathlib.Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    PRIVATE_KEY: str = "nothing"
    PUBLIC_KEY: str = "nothing"
    PROJECT_TITLE: str = "Project Title"
    PROJECT_DESCRIPTION: str = "Project Description"
    TTL: int = 3600

    model_config = SettingsConfigDict(env_file=".env")
