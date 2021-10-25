var provider = null;
var user = null;
var raw_contract = null;
var contract = null;
var initialized = false;
var OPNtoken = null;
var OPNhub = null;

async function init2() {
	const provider = await detectEthereumProvider();
	const chainId = await provider.request({method: 'eth_chainId'});
	console.log(chainId);
}


function init() {
  $('#network').html("starting connection...");
  const {ethereum} = window;
  ethereum.on('chainChanged', (_chainId) => window.location.reload());
  const newAccounts = ethereum.request({method: 'eth_requestAccounts'});
  provider =  new ethers.providers.Web3Provider(ethereum, 'any');
  provider.getNetwork().then((chain) => {$('#network').html(chain.name);});
  //++ const openProvider = new opencontracts.providers.Web3Provider(provider);
  user = provider.getSigner();
  initialized = true;
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
  contractAddress = $.trim(await (await fetch(new URL(link + "/contract.address"))).text());
  contractAbi = await (await fetch(new URL(link + "/contract.abi"))).text();
  console.log(contractAddress);
  console.log(JSON.parse(contractAbi));
  raw_contract = new ethers.Contract(contractAddress, JSON.parse(contractAbi), provider);
  contract = raw_contract.connect(user);
  tokenAddress =  $.trim(await (await fetch('contracts/ropstenToken.address')).text());
  tokenABI = await (await fetch('contracts/ropstenToken.abi')).text();
  OPNtoken = new ethers.Contract(tokenAddress, JSON.parse(tokenABI), provider).connect(user);
  hubAddress =  $.trim(await (await fetch('contracts/ropstenHub.address')).text());
  hubABI = await (await fetch('contracts/ropstenHub.abi')).text();
  OPNhub = new ethers.Contract(hubAddress, JSON.parse(hubABI), provider).connect(user);
       
  // add a button allowing the user to get OPN tokens
  tokenActions = "<p>You need $OPN tokens to call an open contract function that performs an enclave computation. Get it here:</p>"; 
  tokenActions += '<input type="submit" value="Get 10 $OPN" onclick="getTokens()" /><br />'
  tokenActions += "<p>You need to allow the OpenContracts Hub to spend 3 $OPN tokens, otherwise it will reject the final transaction. Do that here:</p>"; 
  tokenActions += '<input type="submit" value="Give Hub access to 3 $OPN" onclick="allowHub()" /><br />'	
  $('#tokenActions').html(tokenActions);
	
  // add a button for every function in the contract
  var contractFunctions = contract.interface.fragments;
  var fnames = "<p><b>Contract Functions:</b></p>";
  for (let i = 1; i < contractFunctions.length; i++) {
    fname = contractFunctions[i].name;
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
    await OPNtoken.increaseAllowance(OPNhub.address, 3);
}

// executed by "Load Contract" button
//function loadContract() {
//  // Connect wallet if necessary
//  if (!initialized) {
//    if (window.ethereum) {
//      init();
//    } else {
//      window.addEventListener('ethereum#initialized', setup, {
//        once: true,
//      });
//      setTimeout(init, 30000); // 30 seconds
//    }
//  }
	
//  // Load Contract
//  var contractAddress = $('#contractAddress').val();
//  var contractABI = JSON.parse($('#contractABI').val());
//  //++ const openContractABI = JSON.parse($('#oracle.py').val());
//  contract = new ethers.Contract(contractAddress, contractABI, provider).connect(user);
//  //++ const openContract = new opencontracts.Contract(contract, openContractABI)
    
//  // add a button for every function in our contract
//  var contractFunctions = contract.interface.fragments;
//  var fnames = "<p><b>Functions:</b></p>";
//  for (let i = 1; i < contractFunctions.length; i++) {
//    fname = contractFunctions[i].name;
//    fnames += `<input id=${fname} type="submit" value="${fname}" onclick="showFunction(${fname})" />`;
//	}
//  fnames += "<br />"
//  $('#functionNames').html(fnames);
//  $('#currentFunction').html("");
//  $('#results').html("");
//}

// executed by clicking on a function button
function showFunction(fname) {
  fname = fname.value;
  var fjson = contract.interface.fragments.filter(x=>x.name==fname)[0];
  var currentFunction = `<p><b>Function name:</b>  ${fname}</p>`;
  currentFunction += `<p><b>State mutability:</b> ${fjson.stateMutability}</p>`;
  currentFunction += '<form id="contractForm" action="javascript:void(0);"> <p><b>Arguments:</b>';
  if (fjson.inputs.length == 0 && fjson.stateMutability!="payable") {currentFunction += " none  <br />"}
  if (fjson.stateMutability=="payable") {
  	currentFunction += `<div>	<label for="msgValue">messageValue (ETH):	</label> <input id="msgValue" type="text" value="0" size="60" /></div>`;
  }
  for (let i = 0; i < fjson.inputs.length; i++) {
  	var input = fjson.inputs[i];
  	var inputname = input.name;
  	if (inputname == null) {inputname = input.type}
  	currentFunction += `<div>	<label for="${inputname}">	${inputname}:	</label> <input id="${inputname}" type="text" value="${input.type}" size="60" /> 	</div>`;
	}
  currentFunction +=`<br /> <input type="submit" value="Call" onclick=callFunction(${fname}) /> </form>`
  $('#currentFunction').html(currentFunction)
  $('#results').html("");
}


// executed by the Call button
async function callFunction(fname) {
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
     if (fjson.stateMutability=="view") {
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
    estimateForwarded = await raw_contract.estimateGas[fn](...call, overrides={from: OPNhub.address});
    estimateCall = await OPNhub.estimateGas["forwardCall(address,bytes4,bytes,bytes,address,bytes)"](contract.address, nonce, calldata, oracleSignature, oracleProvider, registrySignature);
    estimateTotal = estimateForwarded + estimateCall;
    console.log(estimateForwarded, estimateCall, estimateTotal);
    OPNhub.forwardCall(contract.address, nonce, calldata, oracleSignature, oracleProvider, registrySignature, overrides={gasLimit: estimateTotal});
}

async function signHex(hexString) {
    signature = await user.signMessage(ethers.utils.arrayify("0x" + hexString));
    console.log(signature);
    return signature;
}

function hexStringToArrayBuffer(hexString) {
    var pairs = hexString.match(/[\dA-F]{2}/gi);
    var integers = pairs.map(function(s) {return parseInt(s, 16);});
    var array = new Uint8Array(integers);
    return array.buffer;
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
    const cose = hexStringToArrayBuffer(attestation_data);
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
    const RSAraw = hexStringToArrayBuffer(new TextDecoder().decode(attestation_doc['user_data']));
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
    var response = await fetch(oracleUrl)
    var buffer = await response.arrayBuffer();
    return bufferToBase64(buffer);
}

function getOracleIP() {
    var registryIP = $('#registryIP').val();
    console.log("wss://" + registryIP + ":8080/");
    var ws = new WebSocket("wss://" + registryIP + ":8080/");
    ws.onopen = function () {
        console.log("websocket is open now.");
        ws.send(JSON.stringify({fname: 'get_oracle_ip'}));
    }
    ws.onmessage = async function (event) {
        data = JSON.parse(event.data);
        if (data['fname'] == 'return_oracle_ip') {
            var serverIP = data['ip'];
            $('#enclaveProviderIP').val(serverIP);
            ws.close();
        }
    }
}

function connectEnclave() {
    var enclaveProviderIP = $('#enclaveProviderIP').val();
    // var oracleCode =  getOracleString(); // $('#oracleCode').val();	
    var trusted_connection = false;
    console.log("wss://" + enclaveProviderIP + ":8080/")
    var ws = new WebSocket("wss://" + enclaveProviderIP + ":8080/");
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
            let oracleCode = await getOracleCode();
            [ETHkey, AESkey, encryptedAESkey] = await extractContentIfValid(data['attestation']);
            trusted_connection = true;
            ws.send(JSON.stringify({fname: 'submit_AES', encrypted_AES: encryptedAESkey}));
	    ws.send(JSON.stringify({fname: 'submit_signature', signature: await signHex(data['signThis'])}));
            ws.send(JSON.stringify(await encrypt(AESkey, {fname: 'submit_oracle', fileContents: oracleCode})));
            ws.send(JSON.stringify(await encrypt(AESkey, {fname: 'run_oracle'})));
        }
	if (data['fname'] == 'encrypted') {
	    data = await decrypt(AESkey, data);
	    if (data['fname'] == "print") {
                document.getElementById("enclaveOutput").innerHTML += "<code>" + data['string'] + "</code><br>";
            } else if (data['fname'] == "xpra") {
                document.getElementById("enclaveOutput").innerHTML += "Opened " + data['url'] + " in interactive session at  <a href=" + data['session'] + " target='_blank'> this link. </a><br>";
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
		hubTX = "<p>You can now trigger the final transaction to the contract, via the Hub. Make sure you manually set a much higher gas price than the current default. If the TX doesnt complete because it runs out of gas, click the button again.</p>";
	        nonce = '0x' + data['nonce'];
		calldata = '0x' + data['calldata'];
		oracleSig = data['oracleSignature'];
		oracleProvider = data['oracleProvider'];
		registrySig = data['registrySignature'];
                hubTX += `<input type="submit" value="Call Hub" onclick="requestHubTransaction('${nonce}','${calldata}','${oracleSig}','${oracleProvider}','${registrySig}')" /><br />`;
	        $('#hubTX').html(hubTX);
            }
        } 
    };
}


