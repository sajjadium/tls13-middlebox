"use strict";

Components.utils.import("resource://gre/modules/devtools/dbg-server.jsm");
Components.utils.import("resource://gre/modules/devtools/dbg-client.jsm");
Components.utils.import("resource://gre/modules/Task.jsm");

let client = null;

// function debugTab() {
// 	client.mainRoot.listWorkers(resp => {
// 		console.log(resp);
// 	});
//   // Get the list of tabs to find the one to attach to.
//   client.listTabs(response => {
//   	console.log(response);
//   	let tab = response.tabs[response.selected];

//     client.attachTab(tab.actor, (response, tabClient) => {
//       if (!tabClient) {
//         return;
//       }

//       // // Attach to the thread (context).
//       // client.attachThread(response.threadActor, (response, thread) => {
//       //   if (!thread) {
//       //     return;
//       //   }

//       //   threadClient = thread;
//       //   // Attach listeners for thread events.
//       //   threadClient.addListener("paused", onPause);
//       //   threadClient.addListener("resumed", fooListener);
//       //   threadClient.addListener("detached", fooListener);
//       //   threadClient.addListener("framesadded", onFrames);
//       //   threadClient.addListener("framescleared", fooListener);
//       //   threadClient.addListener("scriptsadded", onScripts);
//       //   threadClient.addListener("scriptscleared", fooListener);

//       //   // Resume the thread.
//       //   threadClient.resume();
//       //   // Debugger is now ready and debuggee is running.
//       // });
//     });
//   });
//   // client.listWorkers(response => {
//   // 	console.log(response);
//   // });
// }

function start() {
}

function shutdown() {
}

function install() {
  // Start the server.
  // if (!DebuggerServer.initialized) {
    DebuggerServer.init();
    DebuggerServer.addBrowserActors();
  // }

  // Listen to an nsIPipe
  let transport = DebuggerServer.connectPipe();

  // Start the client.
  client = new DebuggerClient(transport);

  // Attach listeners for client events.
  // client.addListener("tabNavigated", onTab);
  // client.addListener("newScript", onScript);
  client.connect((type, traits) => {
		Task.spawn(function* () {
		  let registrations = [];
		  let workers = [];

		  try {
		    // List service worker registrations
		    ({ registrations } =
		      yield client.mainRoot.listServiceWorkerRegistrations());

		    // List workers from the Parent process
		    ({ workers } = yield client.mainRoot.listWorkers());

		    // And then from the Child processes
		    let { processes } = yield client.mainRoot.listProcesses();
		    for (let process of processes) {
		      // Ignore parent process
		      if (process.parent) {
		        continue;
		      }
		      let { form } = yield client.getProcess(process.id);
		      let processActor = form.actor;
		      let response = yield client.request({
		        to: processActor,
		        type: "listWorkers"
		      });
		      workers = workers.concat(response.workers);
		    }
		  } catch (e) {
		    // Something went wrong, maybe our client is disconnected?
		  }

		  console.log(registrations, workers);
		});
  });
}

function uninstall() {
}
