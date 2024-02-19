import pathlib

from pydantic_settings import BaseSettings, SettingsConfigDict


from typing import List, Optional, Union

# Project Directories
ROOT = pathlib.Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    PRIVATE_KEY: str = "e4f7cafa0b271769087b06859917921941c4cea13abe842f379fc9209f367592"
    PUBLIC_KEY: str = "03fe4920e43e00fcf4b744ba8bfc9b5076c9ad38fedf1f37f3aad62e5471a272fc"
    PROJECT_TITLE: str = "High Assurance did:web"
    PROJECT_DESCRIPTION: str = "High Assurance did:web project"
    TTL: int = 3600

    model_config = SettingsConfigDict(env_file=".env")
   
    
   


    
    
    

   

