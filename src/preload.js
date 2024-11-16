const { contextBridge, ipcRenderer } = require('electron');

// Expose a limited, safe API to the renderer process
contextBridge.exposeInMainWorld('electron', {
    ipcRenderer: {
        send: (channel, data) => {
            // Validate channels if necessary
            const validChannels = ['login-successful','logout-successful'];
            if (validChannels.includes(channel)) {
                ipcRenderer.send(channel, data);
            }
        },
        // Add more methods as needed
        on: (channel, func) => {
            const validChannels = ['some-channel'];
            if (validChannels.includes(channel)) {
                // Strip event to prevent potential leak of extra information
                ipcRenderer.on(channel, (event, ...args) => func(...args));
            }
        }
    }
});
