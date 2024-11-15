// background.js
console.log("background loaded");

let cachedUser = null;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("on message");
  if (message.action === "getUser") {
    getUser()
      .then((user) => {
        sendResponse(user);
      })
      .catch((error) => {
        console.error("Error fetching user:", error);
        sendResponse(null);
      });
    // pri pošiljanju asinhronih sporočil v Chrome-u je potrebno vrniti true, da se sendResponse pošlje
    return true;
  }
});

function getUser() {
  return new Promise((resolve, reject) => {
    if (cachedUser !== null) {
      resolve(cachedUser);
    } else {
      fetch("http://localhost:9000/user")
        .then((response) => {
          if (!response.ok) {
            reject("Network response was not ok");
          } else {
            return response.json();
          }
        })
        .then((user) => {
          cachedUser = user; // Cache the user data
          resolve(user); // Resolve with the fetched user data
        })
        .catch((error) => {
          reject(error); // Reject if there's an error
        });
    }
  });
}
