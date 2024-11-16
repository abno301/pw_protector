document.addEventListener('DOMContentLoaded', function () {
    const fileUpload = document.getElementById('file-upload');
    const fileInput = document.getElementById('sshKey');
    const loginButton = document.getElementById('login-button');

    fileUpload.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            const sshKeyFile = fileInput.files[0];
            const reader = new FileReader();

            reader.onload = (event) => {
                const [username, password] = event.target.result
                    .trim()
                    .split('\n')
                    .map((line) => line.trim());
                localStorage.setItem('username', username);
                localStorage.setItem('password', password);
            };

            reader.onerror = () => {
                alert('Error reading the SSH key file.');
            };

            reader.readAsText(sshKeyFile);
            fileUpload.querySelector('p').textContent = sshKeyFile.name;
            fileUpload.querySelector('.material-icons').style.color = '#66bb6a';
        }
    });

    loginButton.addEventListener('click', (event) => {
        event.preventDefault();
        if (!fileInput.files.length) {
            fileUpload.querySelector('.material-icons').style.color = '#fb0000';
            fileUpload.querySelector('p').textContent = "Please select an SSH key file to proceed";
            fileUpload.querySelector('p').style.color = "red";
        } else {
            window.electron.ipcRenderer.send('login-successful');
        }
    });
});
