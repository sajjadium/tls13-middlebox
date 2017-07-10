function sendUserResponse(msg) {
	browser.runtime.sendMessage(msg);
	browser.windows.remove(browser.windows.WINDOW_ID_CURRENT);
}

document.getElementById("yesBtn").addEventListener("click", function() {
	sendUserResponse("yes");
});

document.getElementById("noBtn").addEventListener("click", function() {
	sendUserResponse("no");
});
