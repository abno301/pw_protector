const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

let mainWindow;

function createWindow(file, options = {}) {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
        },
        ...options,
    });

    mainWindow.loadFile(file);

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

function createLoginWindow() {
    createWindow('views/login.html');
}

function createDashboardWindow() {
    if (mainWindow) {
        mainWindow.loadFile('views/dashboard.html');
    }
}

function handleLogout() {
    if (mainWindow) {
        // Close the current window (dashboard)
        mainWindow.close();
        mainWindow = null;
    }

    createLoginWindow();
}

// Application lifecycle events
app.whenReady().then(createLoginWindow);

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (!mainWindow) {
        createLoginWindow();
    }
});

// IPC event handlers
ipcMain.on('login-successful', () => {
    createDashboardWindow();
});

ipcMain.on('logout-successful', () => {
    handleLogout();
});

module.exports = { createDashboardWindow };
