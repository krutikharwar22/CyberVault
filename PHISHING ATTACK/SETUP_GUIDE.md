# MySQL Database & REST API Setup Guide

## Issues Fixed:
1. ✅ Fixed INSTALLED_APPS syntax errors (missing commas)
2. ✅ Configured Django REST Framework
3. ✅ Created REST API ViewSets for Scan, Alert, and ActivityLog
4. ✅ Added REST API endpoints (/api/scans, /api/alerts, /api/activity)
5. ✅ Fixed duplicate home() function
6. ✅ Added proper Django settings for REST Framework
7. ✅ Created requirements.txt with all dependencies

## Step 1: Install Dependencies
Run this command in your project directory:

```bash
pip install -r requirements.txt
```

**Note:** If you encounter issues with mysqlclient on Windows, you may need:
- Visual C++ Build Tools installed
- Or use MySQL Connector instead: `pip install mysql-connector-python`

## Step 2: Ensure MySQL is Running
Before running migrations, make sure MySQL is running on your system:
- Local MySQL server on 127.0.0.1:3306
- Database name: `phish_db`
- Username: `root`
- Password: `ST@26.04.2005`

## Step 3: Create MySQL Database (if not exists)
Open MySQL command line or use a GUI tool and run:

```sql
CREATE DATABASE IF NOT EXISTS phish_db;
```

## Step 4: Run Migrations
In your Django project directory, run:

```bash
python manage.py migrate
```

This creates all necessary tables in MySQL.

## Step 5: Create Superuser (Optional but Recommended)
```bash
python manage.py createsuperuser
```

## Step 6: Start the Django Development Server
```bash
python manage.py runserver
```

The application will be available at:
- Web Interface: http://localhost:8000
- Admin Panel: http://localhost:8000/admin

## REST API Endpoints

### Authentication Required - Use Session Authentication

#### Scans API
- **GET** `/api/scans/` - List all scans for current user
- **POST** `/api/scans/` - Create a new scan
- **GET** `/api/scans/{id}/` - Get scan details
- **PUT** `/api/scans/{id}/` - Update scan
- **DELETE** `/api/scans/{id}/` - Delete scan

#### Alerts API
- **GET** `/api/alerts/` - List all alerts
- **POST** `/api/alerts/` - Create alert
- **GET** `/api/alerts/{id}/` - Get alert details
- **PUT** `/api/alerts/{id}/` - Update alert
- **DELETE** `/api/alerts/{id}/` - Delete alert

#### Activity Log API
- **GET** `/api/activity/` - List activity logs for current user
- **POST** `/api/activity/` - Create activity log
- **GET** `/api/activity/{id}/` - Get activity details

## Testing the API

### Using cURL:
```bash
# Login first (get session cookie)
curl -X POST http://localhost:8000/login/ \
  -d "identifier=username&password=password" \
  -c cookies.txt

# Access API with session
curl -X GET http://localhost:8000/api/scans/ \
  -b cookies.txt
```

### Using Python Requests:
```python
import requests

session = requests.Session()

# Login
session.post('http://localhost:8000/login/', data={
    'identifier': 'your_username',
    'password': 'your_password'
})

# Access API
response = session.get('http://localhost:8000/api/scans/')
print(response.json())
```

## Troubleshooting

### Issue: mysqlclient installation fails
**Solution:** 
- On Windows: Install MySQL Connector Python instead
  ```bash
  pip install mysql-connector-python
  ```
  Then update settings.py to use:
  ```python
  'ENGINE': 'mysql.connector.django',
  ```

### Issue: "Can't connect to MySQL server"
**Solution:**
- Verify MySQL is running
- Check credentials in settings.py
- Verify database exists: `CREATE DATABASE phish_db;`
- Check host/port settings (127.0.0.1:3306 by default)

### Issue: "ModuleNotFoundError: No module named 'rest_framework'"
**Solution:**
- Run: `pip install -r requirements.txt`
- Verify installation: `pip list | grep djangorestframework`

## Environment Variables (Optional - Best Practice)
For security, create a `.env` file instead of hardcoding credentials:

```
DEBUG=True
SECRET_KEY=your-secret-key
DB_NAME=phish_db
DB_USER=root
DB_PASSWORD=ST@26.04.2005
DB_HOST=127.0.0.1
DB_PORT=3306
```

Then update settings.py to use them with `python-dotenv`.
