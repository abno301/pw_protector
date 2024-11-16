let cachedCredentials = null;
let cachedPasswords = [];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case "getUser":
      const { username, masterPassword } = message.payload;
      getUser(username, masterPassword)
        .then((passwords) => {
          cachedCredentials = { username, masterPassword };
          cachedPasswords = passwords;

          sendResponse(passwords);
        })
        .catch((error) => {
          console.error("Error fetching user passwords:", error);
          sendResponse(null);
        });
      return true;

    case "addPassword":
      const {
        username: u,
        masterPassword: mp,
        password,
        description,
      } = message.payload;
      console.log(password);
      cachedPasswords.passwords.push(password);
      addPassword(u, mp, password, description)
        .then((response) => {
          sendResponse(response);

          console.log("bg-pšass: ", password);
        })
        .catch((error) => {
          console.error("Error adding password:", error);
          sendResponse(null);
        });
      return true;

    case "getUserPassword":
      {
        if (!cachedCredentials) {
          return sendResponse({ error: "Not logged in" });
        }
        sendResponse({
          passwords: cachedPasswords,
          username: cachedCredentials.username,
        });
      }
      return true;
  }
});

async function getUser(username, masterPassword) {
  console.log("login", username, masterPassword);
  const response = await fetch(`http://localhost:5144/password/${username}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      Username: username,
      MasterPassword: masterPassword,
    }),
  });

  if (!response.ok) {
    throw new Error(
      `Failed to fetch user passwords. Status: ${response.status}`
    );
  }

  const passwords = await response.json();
  return passwords;
}

async function createUser(username, masterPassword) {
  console.log("Attempting to register user:", username, password);
  try {
    const response = await fetch("http://localhost:5144/masterPassword", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        Username: username,
        MasterPassword: masterPassword,
      }),
    });

    if (!response.ok) {
      throw new Error(`Failed to create user. Status: ${response.status}`);
    }

    const data = await response.json();
    console.log("User registered successfully:", data);
    return data;
  } catch (error) {
    console.error("Error in createUser function:", error);
    throw error;
  }
}

async function addPassword(username, masterPassword, password, description) {
  const response = await fetch("http://localhost:5144/password", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      Username: username,
      MasterPassword: masterPassword,
      Password: password,
      Description: description,
    }),
  });

  if (!response.ok) {
    throw new Error(`Failed to add password. Status: ${response.status}`);
  }

  const result = await response.json();
  return result;
}
