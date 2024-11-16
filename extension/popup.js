document.getElementById("login-btn").addEventListener("click", () => {
  clearErrorMessage();
  handleAuth();
});

function handleAuth() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  chrome.runtime.sendMessage(
    {
      action: "getUser",
      payload: { username, masterPassword: password },
    },
    (response) => {
      console.log(response);
      if (response) {
        document.getElementById("login-section").style.display = "none";
        document.getElementById("welcome-section").style.display = "block";
        document.getElementById("welcome-username").textContent = username;
        document.getElementById("add-password-btn").style.display = "inline";
      } else {
        document.getElementById("response-message").textContent =
          "Login failed.";
      }
    }
  );
}

document.getElementById("add-password-btn").addEventListener("click", () => {
  document.getElementById("add-password-section").style.display = "block";
});

document
  .getElementById("confirm-add-password")
  .addEventListener("click", () => {
    clearErrorMessage();

    const username = document.getElementById("username").value;
    const masterPassword = document.getElementById("password").value;
    const description = document.getElementById("description").value;
    const password = document.getElementById("new-password").value;

    chrome.runtime.sendMessage(
      {
        action: "addPassword",
        payload: { username, masterPassword, password, description },
      },
      (response) => {
        if (response) {
          alert("Password added successfully!");
          document.getElementById("add-password-section").style.display =
            "none";
          document.getElementById("description").value = "";
          document.getElementById("new-password").value = "";
        } else {
          document.getElementById("response-message").textContent =
            "Failed to add password.";
        }
      }
    );
  });

function clearErrorMessage() {
  document.getElementById("response-message").textContent = "";
}
