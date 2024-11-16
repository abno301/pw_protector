document.addEventListener('DOMContentLoaded', function () {
    const mUsername = localStorage.getItem('username');
    const mPassword = localStorage.getItem('password');

    // Initialize Materialize modals
    const modals = document.querySelectorAll('.modal');
    M.Modal.init(modals);

    const masterPasswordModal = M.Modal.getInstance(document.getElementById('master-password-modal'));
    const masterPasswordInput = document.getElementById('master-password-input');
    const masterPasswordForm = document.getElementById('master-password-form');

    let currentPasswordTextElement; // Store reference to the password text element
    let currentPassword; // Store the actual password


    // Logout button click
    document.getElementById('logout-button').addEventListener('click', () => {
        window.electron.ipcRenderer.send('logout-successful');
    });

    // Add Password form submission
    document.getElementById('add-password-form').addEventListener('submit', function (event) {
        event.preventDefault();

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        fetch('http://localhost:5144/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                Username: mUsername,
                MasterPassword: mPassword,
                Password: password,
                Description: username
            })
        })
            .then((response) => response.json())
            .then((data) => {
                addPasswordToUI({
                    description: username,
                    password: password,
                    _id: data.passwordId
                });
            })
            .catch(() => {
                alert('An error occurred while adding the password.');
            });

        document.getElementById('add-password-form').reset();
        M.Modal.getInstance(document.getElementById('add-password-modal')).close();
    });

    // Backup Passwords button click
    document.getElementById('backup-button').addEventListener('click', fetchAndDisplayPasswords);

    function addPasswordToUI(passwordEntry) {
        const tableBody = document.querySelector('#password-table tbody');
        const row = document.createElement('tr');
        row.classList.add('slide-in');

        const { description = 'No username specified', password = 'No password specified', _id = '' } = passwordEntry;

        row.innerHTML = `
            <td>${description}</td>
            <td><span class="password-text" style="color: lightgrey;">*password hidden*</span></td>
            <td>
                <button class="btn-flat toggle-password-button" data-password="${password}">
                    <i class="material-icons grey-text">visibility</i>
                </button>
                <button class="btn-flat delete-password-button" data-id="${_id}">
                    <i class="material-icons grey-text">delete</i>
                </button>
            </td>
        `;

        tableBody.insertBefore(row, tableBody.firstChild);

        document.querySelectorAll('.toggle-password-button').forEach(button => {
            button.addEventListener('click', function () {
                const passwordTextElement = this.closest('tr').querySelector('.password-text');
                const isHidden = passwordTextElement.textContent === '*password hidden*';

                if (isHidden) {
                    // Store references for use in the modal
                    currentPasswordTextElement = passwordTextElement;
                    currentPassword = this.dataset.password;

                    // Open the modal
                    masterPasswordModal.open();
                } else {
                    // Hide the password
                    passwordTextElement.textContent = '*password hidden*';
                    passwordTextElement.style.color = 'lightgrey';
                    this.querySelector('i').textContent = 'visibility';
                }
            });
        });


        row.querySelector('.delete-password-button').addEventListener('click', function () {
            const passwordId = this.dataset.id;
            if (passwordId) {
                fetch(`http://localhost:5000/api/passwords/${passwordId}`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' }
                })
                    .then((response) => response.json())
                    .then(() => row.remove())
                    .catch(() => alert('An error occurred while deleting the password.'));
            } else if (confirm('Are you sure you want to delete this password entry?')) {
                row.remove();
            }
        });
    }

    // Handle form submission in the modal
    masterPasswordForm.addEventListener('submit', function (event) {
        event.preventDefault();

        const enteredMasterPassword = masterPasswordInput.value;
        const storedMasterPassword = localStorage.getItem('password');

        if (enteredMasterPassword === storedMasterPassword) {
            // Display the password if verified
            currentPasswordTextElement.textContent = currentPassword || 'No password available';
            currentPasswordTextElement.style.color = 'black';
            masterPasswordModal.close();
        } else {
            // Show an error toast or alert
            M.toast({ html: 'Incorrect master password!', classes: 'red' });
        }

        // Reset the input field
        masterPasswordInput.value = '';
    });

    function fetchAndDisplayPasswords() {
        fetch(`http://localhost:5144/password/${mUsername}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ Username: mUsername, MasterPassword: mPassword })
        })
            .then((response) => response.json())
            .then((data) => {
                const tableBody = document.querySelector('#password-table tbody');
                tableBody.innerHTML = '';
                data.passwords.forEach((entry) =>
                    addPasswordToUI({
                        description: entry.description,
                        password: entry.password,
                        _id: entry._id
                    })
                );
            })
            .catch(() => {
                M.toast({ html: 'Error fetching passwords!', classes: 'red' });
            });
    }

    // Fetch passwords on page load
    fetchAndDisplayPasswords();

    // Add slide-in animation styles dynamically
    const styleSheet = document.createElement('style');
    styleSheet.type = 'text/css';
    styleSheet.innerText = `
        @keyframes slideIn {
            0% {
                opacity: 0;
                transform: translateY(-20px);
            }
            100% {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .slide-in {
            animation: slideIn 0.5s ease-out;
        }
    `;
    document.head.appendChild(styleSheet);
});
