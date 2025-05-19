# SentinelAI - Automated Intrusion Detection System

[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![React](https://img.shields.io/badge/React-18.0+-brightgreen.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-purple.svg)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgray.svg)
![Alembic](https://img.shields.io/badge/Migrations-Alembic-orange.svg)

## Overview

SentinelAI is an automated Intrusion Detection System designed to monitor network traffic and system logs for suspicious activities based on a flexible rule-based engine. It features a backend built with Python and FastAPI for processing data and managing rules, and a React-based frontend for visualizing alerts, managing rules, and monitoring system status.

## Key Features

* **Rule-Based Detection:** Define and manage custom rules to detect various types of security threats.
* **Multiple Rule Types:** Supports single event detection, thresholds, sequences of events, coincidences, aggregations, and anomaly detection.
* **Real-time Monitoring:** Processes network data and system logs to identify potential intrusions.
* **Alert Management:** View and manage generated security alerts through the web interface.
* **System Status Monitoring:** Provides insights into the health and activity of the system.
* **Extensible Architecture:** Designed to be easily extended with new rule types and data sources.
* **Database Migrations:** Uses Alembic for managing database schema changes.
* **Modern Web Interface:** User-friendly frontend built with React.

## Project Structure

```plaintext
IDS_Automated/
|
|--- alembic/
|
|---alembic.ini
|
|---sentinealai.db
|
|---database.py
|
|---models.py
|
|---main.py
|
|---sentinel-ai-frontend
	|
	|---node_modules/
	|
	|---package.json
	|
	|---package-lock.json
	|
	|---public/
	|
	|---src/	
	     |
	     |---App.js
	     |
	     |---App.css
	     |
	     |---index.js
	     |
         |---index.css
         |
         |---hooks
         |    |
	     |    |---useApi.js
	     |
	     |---components
	          |
	          |---Alert.js
	          |
	          |---Navigation.js
	          |
	          |---Playground.js
	          |
	          |---Rules.js
	          |
	          |---Status.js
	          |
	          |---Alert.css
	          |
	          |---Navigation.css
	          |
	          |---Rules.css
	          |
	          |---Status.css
```
## Technologies Used

* **Backend:**
    * [Python](https://www.python.org/)
    * [FastAPI](https://fastapi.tiangolo.com/) - Modern, fast (high-performance), web framework for building APIs with Python 3.8+
    * [SQLAlchemy](https://www.sqlalchemy.org/) - SQL toolkit and Object Relational Mapper
    * [SQLite](https://www.sqlite.org/index.html) - Lightweight, disk-based database
    * [Alembic](https://alembic.sqlalchemy.org/en/latest/) - Database migration tool for SQLAlchemy

* **Frontend:**
    * [React](https://react.dev/) - A JavaScript library for building user interfaces
    * [React Router](https://reactrouter.com/) - For declarative routing in React applications
    * [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/) - Package managers for JavaScript dependencies

## Getting Started

### Prerequisites

* [Python 3.8+](https://www.python.org/downloads/)
* [pip](https://pypi.org/project/pip/) (usually installed with Python)
* [Node.js](https://nodejs.org/) (for the frontend)
* [npm](https://www.npmjs.com/) (usually installed with Node.js)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone <your_repository_url>
    cd IDS_Automated
    ```

2.  **Set up the backend:**
    ```bash
    cd .
    pip install -r requirements.txt
    ```

3.  **Configure the database (if necessary):**
    * The project uses SQLite by default (`sentinealai.db`). Alembic is set up for migrations.
    * To run migrations (after making changes to `models.py`):
        ```bash
        alembic upgrade head
        ```

4.  **Run the backend:**
    ```bash
    uvicorn main:app --reload
    ```
    The backend API will likely be accessible at `http://127.0.0.1:8000`.

5.  **Set up the frontend:**
    ```bash
    cd sentinel-ai-frontend
    npm install
    ```

6.  **Run the frontend:**
    ```bash
    npm start
    ```
    The frontend application will likely be accessible at `http://localhost:3000`.

## Configuration

* **Backend:** Configuration options (e.g., database URL, logging settings) might be present in environment variables or within the `database.py` or `main.py` files.
* **Frontend:** API endpoint configuration might be within the React components or the `useApi.js` hook. Ensure the frontend is configured to point to the correct backend API URL.

## Contributing

Contributions are welcome! Please follow these steps:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix (`git checkout -b feature/your-feature-name`).
3.  Make your changes and commit them (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin feature/your-feature-name`).
5.  Open a pull request.

## License

This project is licensed under the [MIT License](License).

	          