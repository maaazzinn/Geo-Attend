document.addEventListener('DOMContentLoaded', function() {
    // Start Attendance button
    const startAttendanceBtn = document.getElementById('start-attendance');
    if (startAttendanceBtn) {
        startAttendanceBtn.addEventListener('click', function() {
            const classInput = document.getElementById('class');
            const subjectInput = document.getElementById('subject');
            
            if (!classInput.value) {
                alert('Please select a class');
                return;
            }
            
            if (!subjectInput.value) {
                alert('Please enter subject');
                return;
            }
            
            // Show loading state
            startAttendanceBtn.disabled = true;
            startAttendanceBtn.textContent = 'Processing...';
            
            // Create form data
            const formData = new FormData();
            formData.append('class', classInput.value);
            formData.append('subject', subjectInput.value);
            
            // Send request
            fetch('/start_attendance', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                // Reset button state
                startAttendanceBtn.disabled = false;
                startAttendanceBtn.textContent = 'Start Attendance';
                
                if (data.success) {
                    // Show results
                    const resultSection = document.getElementById('result-section');
                    const resultBody = document.getElementById('result-body');
                    
                    // Clear previous results
                    resultBody.innerHTML = '';
                    
                    // Add new results
                    data.students.forEach(student => {
                        const row = document.createElement('tr');
                        
                        // Apply color based on status
                        if (student.status === 'Present') {
                            row.className = 'present-row';
                        } else if (student.status === 'Absent') {
                            row.className = 'absent-row';
                        }
                        
                        row.innerHTML = `
                            <td>${student.roll_no}</td>
                            <td>${student.name}</td>
                            <td>${student.status}</td>
                        `;
                        
                        resultBody.appendChild(row);
                    });
                    
                    // Show results section
                    resultSection.style.display = 'block';
                    
                    // Add some styling to the rows
                    const presentRows = document.querySelectorAll('.present-row');
                    const absentRows = document.querySelectorAll('.absent-row');
                    
                    presentRows.forEach(row => {
                        row.style.backgroundColor = '#d4edda';
                    });
                    
                    absentRows.forEach(row => {
                        row.style.backgroundColor = '#f8d7da';
                    });
                    
                    // Hide devices section if visible
                    const devicesSection = document.getElementById('devices-section');
                    if (devicesSection) {
                        devicesSection.style.display = 'none';
                    }
                    
                    // Scroll to results
                    resultSection.scrollIntoView({ behavior: 'smooth' });
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                startAttendanceBtn.disabled = false;
                startAttendanceBtn.textContent = 'Start Attendance';
                alert('An error occurred. Please try again.');
            });
        });
    }
    
    // Scan devices button
    const scanDevicesBtn = document.getElementById('scan-devices');
    if (scanDevicesBtn) {
        scanDevicesBtn.addEventListener('click', function() {
            // Show loading state
            scanDevicesBtn.disabled = true;
            scanDevicesBtn.textContent = 'Scanning...';
            
            // Send request
            fetch('/scan_devices')
            .then(response => response.json())
            .then(data => {
                // Reset button state
                scanDevicesBtn.disabled = false;
                scanDevicesBtn.textContent = 'Scan Devices';
                
                if (data.success) {
                    // Show devices section
                    const devicesSection = document.getElementById('devices-section');
                    const devicesBody = document.getElementById('devices-body');
                    
                    // Clear previous results
                    devicesBody.innerHTML = '';
                    
                    // Add new results
                    data.devices.forEach((device, index) => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${index + 1}</td>
                            <td>${device}</td>
                        `;
                        devicesBody.appendChild(row);
                    });
                    
                    // Show devices section
                    devicesSection.style.display = 'block';
                    
                    // Hide results section if visible
                    const resultSection = document.getElementById('result-section');
                    if (resultSection) {
                        resultSection.style.display = 'none';
                    }
                    
                    // Scroll to devices
                    devicesSection.scrollIntoView({ behavior: 'smooth' });
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                scanDevicesBtn.disabled = false;
                scanDevicesBtn.textContent = 'Scan Devices';
                alert('An error occurred. Please try again.');
            });
        });
    }
    
    // MAC address scanning for student registration
    const scanMacBtn = document.getElementById('scan-mac');
    if (scanMacBtn) {
        // Get modal elements
        const modal = document.getElementById('mac-scan-modal');
        const closeBtn = modal.querySelector('.close');
        const macList = document.getElementById('mac-list');
        
        // Open modal when scan button is clicked
        scanMacBtn.addEventListener('click', function() {
            // Show loading state
            scanMacBtn.disabled = true;
            scanMacBtn.textContent = 'Scanning...';
            
            // Send request
            fetch('/scan_devices')
            .then(response => response.json())
            .then(data => {
                // Reset button state
                scanMacBtn.disabled = false;
                scanMacBtn.textContent = 'Scan';
                
                if (data.success) {
                    // Clear previous results
                    macList.innerHTML = '';
                    
                    // Add new results
                    data.devices.forEach((device, index) => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${index + 1}</td>
                            <td>${device}</td>
                        `;
                        
                        // Add click event to select MAC address
                        row.addEventListener('click', function() {
                            const macInput = document.getElementById('mac_address');
                            macInput.value = device;
                            modal.style.display = 'none';
                        });
                        
                        macList.appendChild(row);
                    });
                    
                    // Show modal
                    modal.style.display = 'block';
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                scanMacBtn.disabled = false;
                scanMacBtn.textContent = 'Scan';
                alert('An error occurred. Please try again.');
            });
        });
        
        // Close modal when X is clicked
        closeBtn.addEventListener('click', function() {
            modal.style.display = 'none';
        });
        
        // Close modal when clicking outside
        window.addEventListener('click', function(event) {
            if (event.target === modal) {
                modal.style.display = 'none';
            }
        });
    }
    
    // Flash message auto-hide
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => {
                alert.style.display = 'none';
            }, 500);
        }, 5000);
    });
});