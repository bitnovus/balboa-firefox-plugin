var {Cc, Ci, Cu, CC, Cr} = require("chrome");

const { atob, btoa } = Cu.import("resource://gre/modules/Services.jsm", {});

var {e} = Cu.import("resource://balboa/trabant.min.jsm");

var BinaryInputStream = CC('@mozilla.org/binaryinputstream;1', 'nsIBinaryInputStream', 'setInputStream');
var BinaryOutputStream = CC('@mozilla.org/binaryoutputstream;1', 'nsIBinaryOutputStream', 'setOutputStream');
var StorageStream = CC('@mozilla.org/storagestream;1', 'nsIStorageStream', 'init');

var pageMod = require("sdk/page-mod");
var warnUser = function(fileName) {
  pageMod.PageMod({
    include: "*.balboa.io",
    contentScriptWhen: "start",
    attachTo: ["existing", "top"],
    contentScriptFile: "resource://balboa/contentscript.js",
    onAttach: function(worker) {
      worker.port.emit("warn", fileName + " failed verification!\nSomeone may be tampering!");}
  });
};

var skeinBlockBytes = 128;
var signingBytes = skeinBlockBytes + 64;

var signingPublicKey = base64ToUint8Array("nrj359niAAv0yzIxrhCO1yQ3zUZ3CkNgn0CrOrV7/KE=");

var module = e; // emscripten uses e
var emscriptenHeap = module["HEAPU8"];

function stringToUint8Array(str) {
  var arr = new Uint8Array(str.length);
  for(var i = 0, j = str.length; i< j; ++i){
    arr[i] = str.charCodeAt(i);
  }
  return arr;
};

function base64ToUint8Array(base64) {
  return stringToUint8Array(atob(base64));
};

var arrayEquals = function(a, b) {
  if (a.length === b.length) {
    var acc = 0;
    for (var i = 0; i < a.length; i++) {
      var x = a[i] ^ b[i];
      acc = acc | x;
    }
    if (acc === 0) { return true; }
    else { return false; }
  }
  else { return false; }
};

var emscripten = function(s) {
  return module[s];   
};

var ccall = emscripten("ccall");

var malloc = function(n) {
  var mallocFn = emscripten("_malloc");
  return mallocFn(n);
};

var free = function(x) {
  var freeFn = emscripten("_free");
  return freeFn(x);
};

var heapSubarray = function(addr, sz) {
  return emscriptenHeap.subarray(addr, addr + sz);
};

var Uint8ArrayToHeap = function(Uint8Buffer) {
  var n = Uint8Buffer.length;
  var buffer = malloc(n);
  heapSubarray(buffer, n).set(Uint8Buffer);
  return buffer;
};

var isValidSignature = function(Uint8PublicKey, Uint8Signature, Uint8Message) {
  var signature = Uint8ArrayToHeap(Uint8Signature);
  var unwrappedHash = malloc(signingBytes);
  var messageHeap = Uint8ArrayToHeap(Uint8Message);
  var publicKey = Uint8ArrayToHeap(Uint8PublicKey);
  var digestResult = malloc(skeinBlockBytes);
  var mlen = malloc(8);

  ccall("skein_hash_once_js",
      null, // void
      ['number', 'number', 'number'], // ptr,ptr,int
      [digestResult, messageHeap, Uint8Message.length]);

  var statusCode = ccall("crypto_sign_ed25519_tweet_open",
      'number', // int
      ['number', 'number', 'number', 'number', 'number', 'number'], // ptr,ptr,ptr,long,ptr
      [unwrappedHash, mlen, signature, signingBytes, 0, publicKey]);

  if (statusCode >= 0) {
    return arrayEquals(heapSubarray(digestResult, skeinBlockBytes),
        heapSubarray(unwrappedHash, skeinBlockBytes));
  }
  else {
    return false;
  }
};

// https://developer.mozilla.org/en-US/docs/Mozilla/Tech/XPCOM/Reference/Interface/NsITraceableChannel
function TracingListener() {
  this.receivedChunks = [];
  this.bytesRead = 0;
  this.responseBody;
  this.responseStatusCode;

  this.deferredDone = {
    promise: null,
    resolve: null,
    reject: null
  };

  this.deferredDone.promise = new Promise(function(resolve, reject) {
    this.resolve = resolve;
    this.reject = reject;
  }.bind(this.deferredDone));

  Object.freeze(this.deferredDone);
  this.promiseDone = this.deferredDone.promise;
};

TracingListener.prototype = {
  onDataAvailable: function(aRequest, aContext, aInputStream, aOffset, aCount) {
    var iStream = new BinaryInputStream(aInputStream); // binaryaInputStream
    var sStream = new StorageStream(8192, aCount, null); // storageStream // must be 8192
    var oStream = new BinaryOutputStream(sStream.getOutputStream(0)); // binaryOutputStream

    this.bytesRead += aCount;

    var data = iStream.readBytes(aCount);
    this.receivedChunks.push(data);

    oStream.writeBytes(data, aCount);

    this.originalListener.onDataAvailable(aRequest, aContext, sStream.newInputStream(0), aOffset, aCount);
  },
  onStartRequest: function(aRequest, aContext) {
    this.originalListener.onStartRequest(aRequest, aContext);
  },
  onStopRequest: function(aRequest, aContext, aStatusCode) {
    this.responseBody = this.receivedChunks.join("");
    delete this.receivedChunks;
    this.responseStatusCode = aStatusCode;

    try {
      var name = aRequest.name.split("/").pop();
      console.log(name);
      var signaturesHeader = aRequest.getResponseHeader("X-Balboa-Signatures");
      console.log("Signatures:", signaturesHeader);

      var signatures = JSON.parse(signaturesHeader);
      var fileSignature = base64ToUint8Array(signatures[name]);

      console.log(signatures);
      console.log(fileSignature);

      var authSucceeded = isValidSignature(signingPublicKey, fileSignature, stringToUint8Array(this.responseBody));

      console.log("valid signature?: ", authSucceeded);

      if (authSucceeded) {
        this.originalListener.onStopRequest(aRequest, aContext, aStatusCode);
      }
      else {
        warnUser(aRequest.name);
        this.originalListener.onStopRequest(aRequest, aContext, Cr.NS_ERROR_ABORT);
      }
    }
    catch (e) {
      warnUser(aRequest.name);
      this.originalListener.onStopRequest(aRequest, aContext, Cr.NS_ERROR_ABORT);
    }

    this.deferredDone.resolve();
  },
  QueryInterface: function(aIID) {
    if (aIID.equals(Ci.nsIStreamListener) || aIID.equals(Ci.nsISupports)) {
      return this;
    }
    throw Cr.NS_NOINTERFACE;
  }
};

var httpRequestObserver = {
  observe: function(subject, topic, data) {
    // Called when request is made.
    if (topic == "http-on-modify-request") {
      var httpChannel = subject.QueryInterface(Ci.nsIHttpChannel);
      if (/app.balboa.io/.test(httpChannel.originalURI.host)
          && (httpChannel.name.contains(".js"))) {
        httpChannel.setRequestHeader("Accept-Encoding", "", false);
        // Don't allow loading from cache.
        subject.loadFlags |= Ci.nsICachingChannel.LOAD_BYPASS_LOCAL_CACHE;
      }
    }

    if (topic == "http-on-examine-response") {
      var httpChannel = subject.QueryInterface(Ci.nsIHttpChannel);
      if (/app.balboa.io/.test(httpChannel.originalURI.host)
          && (httpChannel.responseStatus == 200)
          && ((httpChannel.contentType == "application/javascript")
            || (httpChannel.name.contains(".js")))) {

        var newListener = new TracingListener();
        subject.QueryInterface(Ci.nsITraceableChannel);
        newListener.originalListener = subject.setNewListener(newListener);

        newListener.promiseDone.then(
            function() {
              console.log("Name: ", httpChannel.name);
              console.log("Bytes read: ", newListener.bytesRead);
              console.log('Response: ', newListener.responseBody);
            },
            function(aReason) {
              console.error("Rejected for: ", aReason);
            }).catch(
              function(aCatch) {
                console.error('Error:', aCatch);
              });
      }
    }
  },

  get observerService() {
    return Cc["@mozilla.org/observer-service;1"]
    .getService(Ci.nsIObserverService);
  },

  register: function() {
    this.observerService.addObserver(this, "http-on-modify-request", false);
    this.observerService.addObserver(this, "http-on-examine-response", false);
  },

  unregister: function() {
    this.observerService.removeObserver(this, "http-on-modify-request");
    this.observerService.removeObserver(this, "http-on-examine-response");
  }
};

httpRequestObserver.register();
