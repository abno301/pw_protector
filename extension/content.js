function identifyLoginFields() {
  const fields = {
    username: null,
    email: null,
    password: null,
    top: 100,
    left: 100,
  };

  document.querySelectorAll("input").forEach((input) => {
    const type = input.getAttribute("type");
    const name = input.getAttribute("name") || "";
    const id = input.getAttribute("id") || "";
    const autocomplete = input.getAttribute("autocomplete") || "";

    let inputIsLoginField = false;

    if (
      !fields.password &&
      (type === "password" || autocomplete === "current-password")
    ) {
      fields.password = input;
      inputIsLoginField = true;
    }

    if (
      !fields.username &&
      type === "text" &&
      (name.toLowerCase().includes("user") ||
        id.toLowerCase().includes("user") ||
        autocomplete === "username")
    ) {
      fields.username = input;
      inputIsLoginField = true;
    }

    if (
      !fields.email &&
      (type === "email" ||
        name.toLowerCase().includes("email") ||
        id.toLowerCase().includes("email") ||
        autocomplete === "email")
    ) {
      fields.email = input;
      inputIsLoginField = true;
    }

    if (inputIsLoginField) {
      const rect = input.getBoundingClientRect();
      fields.top = rect.top + rect.height + 10;
      fields.left = rect.left;
      inputIsLoginField = false;
    }
  });
  return fields;
}

function createModal(fields, user) {
  const displayText = user.email || user.username || "password";

  const modalContainer = document.createElement("div");
  modalContainer.id = "custom-modal";
  modalContainer.classList.add("modal-content");

  const modalHeader = document.createElement("div");
  modalHeader.classList.add("modal-item");

  const textContainer = document.createElement("div");
  textContainer.classList.add("modal-text");

  const emailText = document.createElement("span");
  emailText.textContent = displayText;
  emailText.classList.add("modal-email");
  emailText.style.cursor = "pointer";
  emailText.onclick = () => fillLoginFields(user);

  const websiteText = document.createElement("span");
  websiteText.textContent = window.location.hostname;
  websiteText.classList.add("modal-website");

  textContainer.appendChild(emailText);
  textContainer.appendChild(websiteText);

  modalHeader.appendChild(textContainer);

  const otherPasswordsOption = document.createElement("div");
  otherPasswordsOption.textContent = "Other Passwords...";
  otherPasswordsOption.classList.add("modal-option");

  const suggestPasswordOption = document.createElement("div");
  suggestPasswordOption.textContent = "Suggest New Password";
  suggestPasswordOption.classList.add("modal-option");

  modalContainer.appendChild(modalHeader);
  modalContainer.appendChild(otherPasswordsOption);
  modalContainer.appendChild(suggestPasswordOption);

  Object.assign(modalContainer.style, {
    position: "absolute",
    top: `${fields.top}px`,
    left: `${fields.left}px`,
  });

  document.body.appendChild(modalContainer);

  modalContainer.addEventListener("click", (e) => {
    e.stopPropagation();
  });

  document.addEventListener("click", removeModal);
}

function removeModal() {
  const modal = document.getElementById("custom-modal");
  if (modal) {
    modal.remove();
    document.removeEventListener("click", removeModal);
  }
}

function showModalNearInputField(user) {
  const fields = identifyLoginFields();
  createModal(fields, user);
}

function fillLoginFields({ username, email, password }) {
  const fields = identifyLoginFields();

  if (fields.username) {
    fields.username.value = username;
    console.log("Username field filled with provided username.");
  } else {
    console.warn("Username field does not exist.");
  }

  if (fields.email) {
    fields.email.value = email;
    console.log("Email field filled with provided email.");
  } else {
    console.warn("Email field does not exist.");
  }

  if (fields.password) {
    fields.password.value = password;
    console.log("Password field filled with provided password.");
  } else {
    console.warn("Password field does not exist.");
  }
}

async function main() {
  console.log("main");
  /*
    when on website scan for inputs, 
    if inputs then request the backend to give me user password, email and username
    show modal
    delete modal
  */
  const loginFields = identifyLoginFields();

  if (loginFields.email || loginFields.username || loginFields.password) {
    chrome.runtime.sendMessage({ action: "getUserPassword" }, (response) => {
      if (response.username && response.passwords) {
        console.log("User data:", response);

        showModalNearInputField({
          username: response.username,
          password: response.passwords[0],
        });
      } else {
        console.warn(response.error);
      }
    });
  }
}

main();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "showModal") {
    main();
    console.log("Showing modal");
  }
});
