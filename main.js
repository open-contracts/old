var provider = null;
var user = null;
var raw_contract = null;
var interface = null;
var contract = null;
var initialized = false;
var OPNtoken = null;
var OPNhub = null;
var OPNforwarder = null;
var oracleFolder = null;

function init() {
  $('#network').html("starting connection...");
  const {ethereum} = window;
  ethereum.on('chainChanged', (_chainId) => window.location.reload());
  const newAccounts = ethereum.request({method: 'eth_requestAccounts'});
  provider =  new ethers.providers.Web3Provider(ethereum, 'any');
  provider.getNetwork().then((chain) => {$('#network').html(chain.name);});
  user = provider.getSigner();
  initialized = true;
  document.getElementById('getOracleIP').submit.disabled=false;
}


// executed by "Load Contract" button
async function loadOpenContract() {
  // Connect wallet if necessary
  if (!initialized) {
    if (window.ethereum) {
      init();
    } else {
      window.addEventListener('ethereum#initialized', setup, {
        once: true,
      });
      setTimeout(init, 30000); // 30 seconds
    }
  }

  // Load Contracts
  var link = "https://raw.githubusercontent.com/" + $('#contractGithub').val();
  var network = (await provider.getNetwork()).name;
  interface = JSON.parse(await (await fetch(new URL(link + "/interface.json"))).text());
  $('#contractName').html("<h1>" + interface["name"] + "</h1>");
  if (interface["network"] != network) {$('#network').html(network + "  !!! Wrong network. Change to " + interface["network"] + " to proceed.")}
  raw_contract = new ethers.Contract(interface['address'], interface['abi'], provider);
  contract = raw_contract.connect(user);
  oc_interface = JSON.parse(await (await fetch('opencontracts_interface.json')).text())[network];
  OPNtoken = new ethers.Contract(oc_interface['token']['address'], oc_interface['token']['abi'], provider).connect(user);
  //raw_forwarder = new ethers.Contract(oc_interface['forwarder']['address'], oc_interface['forwarder']['abi'], provider);
  OPNforwarder = new ethers.Contract(oc_interface['forwarder']['address'], oc_interface['forwarder']['abi'], provider).connect(user);
  OPNhub = new ethers.Contract(oc_interface['hub']['address'], oc_interface['hub']['abi'], provider).connect(user);
  

  // add a button allowing the user to get OPN tokens
  tokenActions = "<p>You need $OPN tokens to call an open contract function that performs an enclave computation. Get it here:</p>"; 
  tokenActions += '<input type="submit" value="Get 10 $OPN" onclick="getTokens()" /><br />'
  tokenActions += "<p>You need to allow the OpenContracts Hub to spend 3 $OPN tokens, otherwise it will reject the final transaction. Do that here:</p>"; 
  tokenActions += '<input type="submit" value="Give Hub access to 3 $OPN" onclick="allowHub()" /><br /><hr>'	
  $('#tokenActions').html(tokenActions);

  // add a button for every function in the contract
  //var contractFunctions = contract.interface.fragments;
  var fnames = "<p><b>Contract Functions:</b></p>";
  for (let i = 1; i < interface['abi'].length; i++) {
    fname = interface['abi'][i].name;
    fnames += `<input id=${fname} type="submit" value="${fname}" onclick="showFunction(${fname})" />`;
	}
  fnames += "<br />"
  $('#functionNames').html(fnames);
  $('#currentFunction').html("");
  $('#results').html("");
}


async function getTokens() {
    await OPNtoken.gimmeSomeMoreOfDemCoins();
}

async function allowHub() {
    await OPNtoken.approve(OPNhub.address, 3);
}

// executed by clicking on a function button
function showFunction(fname) {
  fname = fname.value;
  //var fjson = contract.interface.fragments.filter(x=>x.name==fname)[0];
  var fjson = interface['abi'].filter(x=>x.name==fname)[0];
  var requires_oracle = (fjson.oracle_folder != undefined)
  var currentFunction = `<p><b>Function name:</b>  ${fname}</p>`;
  currentFunction += `<p><b>State mutability:</b> ${fjson.stateMutability}</p>`;
  currentFunction += '<form id="contractForm" action="javascript:void(0);"> <p><b>Arguments:</b>';
  if ((fjson.inputs.length == 0 || requires_oracle) && fjson.stateMutability!="payable") {currentFunction += " none  <br />"}
  if (fjson.stateMutability=="payable") {
      currentFunction += `<div>	<label for="msgValue">messageValue (ETH):	</label> <input id="msgValue" type="text" value="0" size="60" /></div>`;
  }
  if (requires_oracle) {
      currentFunction +=`<br /> <input id="getOracleFolder" type="submit" value="Load Oracle Data" onclick="getOracleFoldr('${fjson.oracle_folder}')"/> </form>`;
      currentFunction +=`<br /> <input id="callButton" type="submit" value="Call" onclick=getOracleIP() disabled="true"/> </form>`;
  } else {
      for (let i = 0; i < fjson.inputs.length; i++) {
          var input = fjson.inputs[i];
  	  var inputname = input.name;
  	  if (inputname == null) {inputname = input.type}
  	  currentFunction += `<div>	<label for="${inputname}">	${inputname}:	</label> <input id="${inputname}" type="text" value="${input.type}" size="60" /> 	</div>`;
      }  
      currentFunction +=`<br /> <input id="callButton" type="submit" value="Call" onclick="callFunction(${fname})" /> </form>`;
  }
  
  $('#currentFunction').html(currentFunction)
  $('#results').html("");
}



async function getOracleFoldr(dir) {
    document.getElementById("getOracleFolder").value = "loading...";
    document.getElementById("getOracleFolder").disabled = true;
    const [user, repo, ref] =  $('#contractGithub').val().split("/");
    var links = await GITHUB_FILES.content_links_json(user, repo, ref, dir);
    var downloads = Promise.all(Object.entries(links).map(async ([file, link]) => [file, await downloadAsBase64(link)]));
    oracleFolder = Object.fromEntries(await downloads);
    document.getElementById("callButton").disabled = false;
    document.getElementById("getOracleFolder").value = "loaded.";
}

async function getOracleIP() {
    document.getElementById("callButton").disabled = true;
    var registryIP = await OPNhub.registryIpList(0);
    var registryIP = hexStringToArray(registryIP).join(".");
    $('#registryIP').val(registryIP);
    console.log("wss://" + registryIP + ":8080/");
    var ws = new WebSocket("wss://" + registryIP + ":8080/");
    ws.onopen = function () {
        console.log("websocket is open now.");
        ws.send(JSON.stringify({fname: 'get_oracle_ip'}));
    }
    ws.onmessage = async function (event) {
        data = JSON.parse(event.data);
        if (data['fname'] == 'return_oracle_ip') {
            var oracleIP = data['ip'];
	    if (oracleIP  == "N/A") {
                document.getElementById("callButton").disabled = false;
		$('#oracleIP').val("Curently none available. Try again in a bit.");
	    } else {
                $('#oracleIP').val(oracleIP);
                ws.close();
	        setTimeout(() => {document.getElementById("enclaveOutput").innerHTML += "Connecting to enclave... <br>"; connectOracle()}, 11000);
	    }
        }
    }
}

// executed by the Call button
async function callFunction(fname) {
   document.getElementById("callButton").disabled = true;
   fname = fname.value;
   var fjson = contract.interface.fragments.filter(x=>x.name==fname)[0];
   var args = [];
   for (let i = 0; i < fjson.inputs.length; i++) {
     	var input = fjson.inputs[i];
     	var inputname = input.name;
     	if (inputname == null) {inputname = input.type}
   		args.push($(`#${inputname}`).val());
   }

   if (fjson.stateMutability=="payable") {
      var msgVal = ethers.utils.parseEther($("#msgValue").val());
      args.push({value: msgVal});
   }

   try {
   	 var txReturn = await contract.functions[fname].apply(this, args);
     if (fjson.stateMutability=="view" || fjson.stateMutability=="pure") {
    	 $('#results').html(txReturn.map(x => x.toString()));
     } else {
       $('#results').html("Waiting for confirmation...");
       await txReturn.wait();
     	 $('#results').html("Confirmed!");
     }
     console.log(txReturn);
   } catch(error) {
     $('#results').html(error.message);
   }

}


async function requestHubTransaction(nonce, calldata, oracleSignature, oracleProvider, registrySignature) {
    console.log(nonce, calldata, oracleSignature, oracleProvider, registrySignature);
    fn = Object.getOwnPropertyNames(contract.interface.functions).filter(sig => contract.interface.getSighash(sig) == calldata.slice(0,10))[0];
    call = contract.interface.decodeFunctionData(calldata.slice(0,10), calldata);
    estimateHub = await OPNhub.estimateGas["forwardCall(address,bytes4,bytes,bytes,address,bytes)"](contract.address, nonce, calldata, oracleSignature, oracleProvider, registrySignature);
    //estimateForwarder = await raw_forwarder.estimateGas["forwardCall(address,bytes)"](contract.address, calldata, overrides={from: OPNhub.address});
    estimateContract = await raw_contract.estimateGas[fn](...call, overrides={from: OPNforwarder.address});
    estiamteTotal = estimateHub.add(estimateContract);
    OPNhub.forwardCall(contract.address, nonce, calldata, oracleSignature, oracleProvider, registrySignature, overrides={gasLimit: estiamteTotal});
}

async function signHex(hexString) {
    signature = await user.signMessage(ethers.utils.arrayify("0x" + hexString));
    console.log(signature);
    return signature;
}

function hexStringToArray(hexString) {
    var pairs = hexString.match(/[\dA-F]{2}/gi);
    var integers = pairs.map(function(s) {return parseInt(s, 16);});
    return new Uint8Array(integers);
}


function b64Url2Buff(b64urlstring) {
  return new Uint8Array(atob(b64urlstring.replace(/-/g, '+').replace(/_/g, '/')).split('').map(val => {
    return val.charCodeAt(0);
  }));
}

function bufferToBase64(buffer) {
    return btoa(new Uint8Array(buffer).reduce((data, byte)=> {
      return data + String.fromCharCode(byte);
    }, ''));
}


const rootcert = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`;


// extracts pubkeys and enclave hash if attestation doc is valid
async function extractContentIfValid(attestation_data) {
    // decode COSE_SIGN1 message
    const cose = hexStringToArray(attestation_data).buffer;
    const cose_sign1_struct = CBOR.decode(cose);
    const array = new Uint8Array(cose_sign1_struct[2]);
    const attestation_doc = CBOR.decode(array.buffer);

    // check attestation signature
    const certificate = new x509.X509Certificate(new Uint8Array(attestation_doc['certificate']));
    await certificate.publicKey.export()
    .then(key=>window.crypto.subtle.exportKey("jwk", key))
    .then(function (key) {b64Url2Buff(key['y']); return key})
    .then(key=>COSE.verify(b64Url2Buff(key['x']), b64Url2Buff(key['y']), cose));

    // check certificate path
    root = new x509.X509Certificate(rootcert);
    var certs = [root];
    const cabundle = attestation_doc['cabundle'];
    for (var i=1; i<cabundle.length; i++) {
        var cert = new Uint8Array(cabundle[i]);
        var cert = new x509.X509Certificate(cert);
        certs.push(cert);
    }
    const chain = new x509.X509ChainBuilder({certificates: certs});
    const items = await chain.build(certificate);
    const validcertpath = await root.equal(items[items.length-1]);
    if (!validcertpath) {throw Error('Invalid Certpath in Attestation')}

    // extracts hash + pubkeys
    const hash = attestation_doc['pcrs'][0];
    console.log("------->UNCHECKED< ENCLAVE HASH:--------", hash);
    // TODO: Add hash ceck
    const ETHkey = new TextDecoder().decode(attestation_doc['public_key']);
    const RSAraw = hexStringToArray(new TextDecoder().decode(attestation_doc['user_data'])).buffer;
    const RSAkey = await crypto.subtle.importKey('spki', RSAraw, {name: "RSA-OAEP", hash: "SHA-256"}, true, ["encrypt"]);
    const AESkey = await crypto.subtle.generateKey({"name":"AES-GCM","length":256},true,['encrypt','decrypt']);
    const rawAES = new Uint8Array(await crypto.subtle.exportKey('raw', AESkey));
    const encryptedAESkey = await Base64.fromUint8Array(new Uint8Array(await window.crypto.subtle.encrypt({name: "RSA-OAEP"}, RSAkey, rawAES)));
    return [ETHkey, AESkey, encryptedAESkey];
}

async function encrypt(AESkey, json) {
    var nonce = window.crypto.getRandomValues(new Uint8Array(12));
    var data = new TextEncoder().encode(JSON.stringify(json));
    var ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce}, AESkey, data));
    var encrypted = new (ciphertext.constructor)(ciphertext.length + nonce.length);
    encrypted.set(ciphertext);
    encrypted.set(nonce, ciphertext.length);
    var encryptedB64 = Base64.fromUint8Array(new Uint8Array(encrypted));
    return {fname: "encrypted", payload: encryptedB64};
}

async function decrypt(AESkey, json) {
    var encrypted = Base64.toUint8Array(json['payload']);
    var ciphertext = encrypted.slice(0, encrypted.length-12);
    var nonce = encrypted.slice(encrypted.length-12, encrypted.length);
    var decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce}, AESkey, ciphertext);
    return JSON.parse(new TextDecoder().decode(decrypted));
}

async function getOracleCode() {
    var oracleBundleLink =  "https://raw.githubusercontent.com/" + $('#contractGithub').val() + "/bundle/oracle_bundle.zip";
    var oracleUrl = new URL(oracleBundleLink);
    var response = await fetch(oracleUrl);
    var buffer = await response.arrayBuffer();
    return bufferToBase64(buffer);
}

async function downloadAsBase64(link) {
    var url = new URL(link);
    var response = await fetch(url);
    return bufferToBase64(await response.arrayBuffer());
}



function connectOracle() {
    var oracleIP = $('#oracleIP').val();
    var trusted_connection = false;
    console.log("wss://" + oracleIP + ":8080/")
    var ws = new WebSocket("wss://" + oracleIP + ":8080/");
    var ETHkey = null;
    var AESkey = null;
    var encryptedAESkey = null;
    ws.onopen = function(event) {
        console.log("WebSocket is open now."); 
        ws.send(JSON.stringify({fname: 'get_attestation'}));
    };
    ws.onmessage = async function (event) {
        data = JSON.parse(event.data);
        if (data['fname'] == "attestation" && !trusted_connection) {
            //let oracleSubmission = {fname: 'submit_oracle', fileContents: await getOracleCode()};
            [ETHkey, AESkey, encryptedAESkey] = await extractContentIfValid(data['attestation']);
            trusted_connection = true;
            ws.send(JSON.stringify({fname: 'submit_AES', encrypted_AES: encryptedAESkey}));
	    ws.send(JSON.stringify({fname: 'submit_signature', signature: await signHex(data['signThis'])}));
	    oracleFolder.fname = 'submit_oracle';
            ws.send(JSON.stringify(await encrypt(AESkey, oracleFolder)));
            ws.send(JSON.stringify(await encrypt(AESkey, {fname: 'run_oracle'})));
        } else if (data['fname'] == "busy") {
	    document.getElementById("enclaveOutput").innerHTML += "<code> Oracle is busy. Request a new IP.</code><br>";
	}
	if (data['fname'] == 'encrypted') {
	    data = await decrypt(AESkey, data);
	    if (data['fname'] == "print") {
                document.getElementById("enclaveOutput").innerHTML += "<code>" + data['string'] + "</code><br>";
            } else if (data['fname'] == "xpra") {
		setTimeout(() => {document.getElementById("enclaveOutput").innerHTML += "Opened " + data['url'] + " in interactive session at  <a href=" + data['session'] + " target='_blank'> this link. </a><br>";; }, 5000);
            } else if (data['fname'] == 'user_input') {
                formID = Math.floor(Math.random() * 100000);
                submitForm = '<form action="javascript:void(0);" id="' + formID + '"> <label for="input">' + data["message"] + '</label>'
                submitForm += '<input type="text" id="input" name="input" value=""> <input type="submit" value="Submit" name="submit"> </form>';
                document.getElementById("enclaveOutput").innerHTML += submitForm;
                form = document.getElementById(formID);
                form.addEventListener('submit', async function() {
                    form.input.disabled = true;
                    form.submit.disabled = true;
                    ws.send(JSON.stringify(await encrypt(AESkey, {fname: 'user_input', input: form.input.value})));
                })
            } else if (data['fname'] == 'submit') {
                document.getElementById("enclaveOutput").innerHTML += "Received oracle results. Requesting transaction to the Open Contracts Hub.";
		hubTX = "<p>You can now trigger the final transaction to the contract, via the Hub.</p>";
	        nonce = '0x' + data['nonce'];
		calldata = '0x' + data['calldata'];
		oracleSig = data['oracleSignature'];
		oracleProvider = data['oracleProvider'];
		registrySig = data['registrySignature'];
                hubTX += `<input type="submit" value="Call Hub" onclick="requestHubTransaction('${nonce}','${calldata}','${oracleSig}','${oracleProvider}','${registrySig}')" /><br />`;
	        $('#hubTX').html(hubTX);
            }
        } else if (data['fname'] == 'error') {
	    document.getElementById("enclaveOutput").innerHTML += "Error! Traceback: <code>" + data['traceback'] + "</code><br>";
	} else if (data['fname'] == 'shutdown') {
	    document.getElementById("enclaveOutput").innerHTML += "Enclave shut down.";
	}
    };
}


