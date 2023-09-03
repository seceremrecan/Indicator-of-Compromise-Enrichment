# IoC (Indicator of Compromise) Enrichment Project

This project is designed as a tool to analyze given IoCs (Indicators of Compromise) and store the obtained data in a database. The project also functions as a FastAPI web application.

## Project Objectives

- Analyze specified IoCs across different sources.
  
- Perform analysis processes asynchronously.
  
- Query IoC types via the "/search" endpoint.
  
- Pay attention to specific fields during analysis (geometric location, malicious control, blacklist, whois).
  
- Store analysis results in a PostgreSQL database.

## Technologies Used

- Python 3.11
- PostgreSQL
- FastAPI (https://fastapi.tiangolo.com/)
- SQLAlchemy ORM (https://docs.sqlalchemy.org/)
- Docker Compose
- Poetry (https://python-poetry.org/docs/)


## Running the Project

1. First, clone this repository: `git clone https://github.com/your-username/project-name.git`.
2. Start the project using Docker Compose: `docker-compose up --build`.
3. The FastAPI web application should now be running at `http://localhost:8000`.
4. Before you start working on the project, you can use Poetry to install the required Python dependencies: `poetry install`.


## Usage

The project offers a simple and convenient way to query IoC types using the "/search" endpoint:

# Query IoC Types

-> HTTP Method: POST
-> URL: `http://localhost:8000/search?type=example_type`
-> To retrieve IoCs of a specific type, make a POST request to the "/search" endpoint, specifying the desired IoC type as a query parameter. The endpoint will respond with the relevant IoCs matching the specified type.





