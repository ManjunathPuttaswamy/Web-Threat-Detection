import importlib.metadata

packages = [
    "numpy",
    "pandas",
    "matplotlib",
    "seaborn",
    "scipy",
    "scikit-learn",
    "xgboost",
    "statsmodels",
    "imbalanced-learn",
    "ipykernel",
    "python-dotenv",
    "fastapi",
    "structlog",
    "tavily-python",    # if error, try "tavily_python"
    "pydantic",
    "wikipedia",
    "uvicorn",
    "httpx",
    "aiofiles",
    "sqlalchemy",
    "bcrypt",
    "reportlab",
    "python-docx",
    "passlib"
]

for pkg in packages:
    try:
        version = importlib.metadata.version(pkg)
        print(f"{pkg}=={version}")
    except importlib.metadata.PackageNotFoundError:
        print(f"{pkg} (not installed)")
