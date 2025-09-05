import os

# class Config:
#     SQLALCHEMY_DATABASE_URI = (
#         f"postgresql+psycopg2://{os.getenv('DB_USER', 'postgres')}:"
#         f"{os.getenv('DB_PASSWORD', 'Musa')}@"
#         f"{os.getenv('DB_SERVER', 'ethics-db')}:"
#         f"{os.getenv('DB_PORT', '5432')}/"
#         f"{os.getenv('DB_NAME', 'ethics')}"
#     )
#     SQLALCHEMY_TRACK_MODIFICATIONS = False


class Config:
    SQLALCHEMY_DATABASE_URI = (
        f"postgresql+psycopg2://{os.getenv('DB_USER', 'postgres')}:"
        f"{os.getenv('DB_PASSWORD', 'malvapudding78*')}@"
        f"{os.getenv('DB_SERVER', 'ethics-db')}:"
        f"{os.getenv('DB_PORT', '5432')}/"
        f"{os.getenv('DB_NAME', 'ethics')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False


    