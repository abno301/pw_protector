// popup.js

/*
ui
api klice z mock serverjem
  1. login 
  2. register
  3. password
login 
when password fields detected send api to backend, specific user should have seved following for each password: website, username/email, password
  when you get response fill
*/

document.getElementById("show-modal-btn").addEventListener("click", () => {
  console.log("button");
  chrome.runtime.sendMessage({ action: "showModal" });
});
