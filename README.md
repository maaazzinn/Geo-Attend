# GeoAttend: Smart Wi-Fi-Based Attendance System

GeoAttend is a lightweight, intelligent attendance system built for classroom environments. It automates student attendance by detecting devices connected to the classroom's Wi-Fi network and matching their MAC addresses against a pre-registered student database.

## 📋 Features

- 🔐 **Secure Login:** Admin/Teacher login
- 🧑‍🎓 **Student Registration:** Add Name, Class, Roll No, and MAC Address
- 🏷 **Class & Subject Selection** before taking attendance
- 📡 **Live Device Scanning** via `arp -a`
- ✅ **Auto-Matching & Marking** of attendance
- 📊 **Attendance Dashboard** with date & class filters
- 📁 **Export to CSV** option for record-keeping
- ✏️ **Manage Students:** Edit/Delete existing records

## 🚀 Installation and Setup

### Prerequisites
- Python 3.6 or higher
- Windows OS (the `arp -a` command is Windows-specific in this implementation)

### Setup Instructions

1. **Clone the repository:**
   ```
   git clone https://github.com/yourusername/geoattend.git
   cd geoattend
   ```

2. **Create a virtual environment (optional but recommended):**
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use: venv\Scripts\activate
   ```

3. **Install required packages:**
   ```
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```
   python app.py
   ```

5. **Access the web interface:**
   Open your browser and go to `http://localhost:5000`

## 🔑 Default Login Credentials

- **Username:** icet
- **Password:** icet123

## 📱 Using the Application

### Taking Attendance

1. Log in using the provided credentials
2. On the dashboard, select the class and subject
3. Click "Start Attendance"
4. The system will scan for connected devices and match their MAC addresses
5. View the attendance results

### Adding a Student

1. Navigate to "Students" from the navigation bar
2. Fill in the student details (Name, Class, Roll No)
3. Either manually enter the MAC address or click "Scan" to detect it
4. Click "Add Student"

### Viewing Attendance History

1. Navigate to "History" from the navigation bar
2. Use the filters to narrow down results by date, class, or subject
3. View the attendance records
4. Export to CSV if needed

## ⚠️ Limitations

- The system currently uses `arp -a` which is Windows-specific. For other operating systems, this command will need to be adjusted.
- Students must be connected to the same Wi-Fi network as the device running the application.
- MAC address spoofing could potentially be used to forge attendance (although this requires technical knowledge).

## 🧠 How It Works

The system works by:
1. Scanning the local network using the `arp -a` command
2. Extracting MAC addresses from the scan results
3. Comparing these MAC addresses against the registered student database
4. Marking students as present when a match is found

## 📁 Project Structure

```
geoattend/
│
├── app.py                 # Core backend logic and Flask routes
├── database.db            # SQLite database
├── requirements.txt       # Required Python libraries
│
├── static/
│   ├── css/
│   │   └── style.css      # Custom styles
│   └── js/
│       └── script.js      # UI interaction scripts
│
├── templates/
│   ├── login.html         # Login page
│   ├── dashboard.html     # Dashboard & attendance initiation
│   ├── students.html      # Student management
│   ├── edit_student.html  # Edit student form
│   ├── history.html       # Attendance history view
│   └── navbar.html        # Navigation bar template
│
└── README.md              # Setup guide and project description
```

## 🔒 Security Considerations

- The application uses hardcoded credentials for simplicity. In a production environment, implement proper authentication.
- Consider encrypting sensitive data, especially MAC addresses, in a production environment.
- Implement rate limiting to prevent brute force attacks.

## 🤝 Contributing

Feel free to fork this project and submit pull requests. You can also open issues if you find bugs or have feature requests.

## 📄 License

This project is released under the MIT License.
