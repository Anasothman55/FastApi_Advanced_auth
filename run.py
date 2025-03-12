

import uvicorn

if __name__ == "__main__":
  uvicorn.run("app.main:app",host="0.0.0.0", port=8000, reload=True)


"""
alembic
1- alembic init -t async migrations
2-  alembic revision --autogenerate -m "1st migrations"
3- alembic upgrade ffd144831b5d    
""" 




