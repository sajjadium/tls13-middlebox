var port = browser.runtime.connect();

port.onMessage.addListener(function() {
	browser.notifications.create("notification", {
		"type": "basic",
		"title": "TLS failure",
		"message": "There is a problem. Please click on this notification to show the full message."
	});
});

browser.notifications.onClicked.addListener(function() {
	browser.windows.create({
		type: "detached_panel",
		url: "form.html",
		width: 250,
		height: 100
	}).then(function(windowInfo) {
		console.log(windowInfo);
	}, function(error) {
	});
});
