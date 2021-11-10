function hexStringToArray(hexString) {
    var pairs = hexString.match(/[\dA-F]{2}/gi);
    var integers = pairs.map(function(s) {return parseInt(s, 16);});
    return new Uint8Array(integers);
}

function b64Url2Buff(b64urlstring) {
  return new Uint8Array(atob(b64urlstring.replace(/-/g, '+').replace(/_/g, '/')).split('').map(
	  val => {return val.charCodeAt(0);}
  ));
}


const awsNitroRootCert = `-----BEGIN CERTIFICATE-----
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
    const root = new x509.X509Certificate(awsNitroRootCert);
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
    if (!validcertpath) {throw new Error('Invalid Certpath in Attestation')}

    // extracts hash + pubkeys
    const hash = attestation_doc['pcrs'][0];
    console.warn("------->UNCHECKED< ENCLAVE HASH:--------", hash);
    // TODO: Add hash ceck
    const ETHkey = new TextDecoder().decode(attestation_doc['public_key']);
    const RSAraw = hexStringToArray(new TextDecoder().decode(attestation_doc['user_data'])).buffer;
    const RSAkey = await crypto.subtle.importKey(
	    'spki', RSAraw, {name: "RSA-OAEP", hash: "SHA-256"}, true, ["encrypt"]
    );
    const AESkey = await crypto.subtle.generateKey(
	    {"name":"AES-GCM","length":256},true,['encrypt','decrypt']
    );
    const rawAES = new Uint8Array(await crypto.subtle.exportKey('raw', AESkey));
    const encryptedAESkey = await Base64.fromUint8Array(
	    new Uint8Array(await window.crypto.subtle.encrypt({name: "RSA-OAEP"}, RSAkey, rawAES))
    );
    return [ETHkey, AESkey, encryptedAESkey];
}



async function requestHubTransaction(opencontracts, nonce, calldata, oracleSignature, oracleProvider, registrySignature) {
    fn = Object.getOwnPropertyNames(opencontracts.contract.interface.functions).filter(
	    sig => opencontracts.contract.interface.getSighash(sig) == calldata.slice(0,10)
    )[0];
    call = opencontracts.contract.interface.decodeFunctionData(calldata.slice(0,10), calldata);
    estimateHub = await opencontracts.OPNhub.connect(opencontracts.signer).estimateGas[
	    "forwardCall(address,bytes4,bytes,bytes,address,bytes)"
    ](
	    opencontracts.contract.address, nonce, calldata, oracleSignature, oracleProvider, registrySignature
    );
    //estimateForwarder = await opencontracts.OPNforwarder.estimateGas["forwardCall(address,bytes)"](
    //   opencontracts.contract.address, calldata, overrides={from: OPNhub.address});
    estimateContract = await opencontracts.contract.estimateGas[fn](...call, overrides={from: OPNforwarder.address});
    estimateTotal = estimateHub.add(estimateContract);
    opencontracts.OPNhub.connect(opencontracts.signer).forwardCall(
	    opencontracts.contract.address, nonce, calldata, oracleSignature,
	    oracleProvider, registrySignature, overrides={gasLimit: estimateTotal}
    );
}

async function encrypt(AESkey, json) {
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(json));
    const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce}, AESkey, data));
    var encrypted = new (ciphertext.constructor)(ciphertext.length + nonce.length);
    encrypted.set(ciphertext);
    encrypted.set(nonce, ciphertext.length);
    const encryptedB64 = Base64.fromUint8Array(new Uint8Array(encrypted));
    return {fname: "encrypted", payload: encryptedB64};
}

async function decrypt(AESkey, json) {
    const encrypted = Base64.toUint8Array(json['payload']);
    const ciphertext = encrypted.slice(0, encrypted.length-12);
    const nonce = encrypted.slice(encrypted.length-12, encrypted.length);
    const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce}, AESkey, ciphertext);
    return JSON.parse(new TextDecoder().decode(decrypted));
}

async function enclaveSession(opencontracts, f) {
    var registryIP = hexStringToArray(await opencontracts.OPNhub.registryIpList(0)).join(".");
    console.warn(`Trying to connect to registry with IP ${registryIP}.`);
    var ws = new WebSocket("wss://" + registryIP + ":8080/");
    var secondsPassed = 0;
    var timer = setInterval(() => {secondsPassed++; if (secondsPassed>30) {clearInterval(timer)}}, 1000);
    ws.onerror = function(event) {
        if (secondsPassed < 10) {
            f.errorHandler("Early WebSocket failure. Probable reason: registry root cert not trusted by the client.")
	    // throw new Error("Early WebSocket failure. Probable reason: registry root cert not trusted by the client.");
	} else {
        f.errorHandler("Late WebSocket failure. Probable reason: no registry available at this IP.")
	}
    }; 
    ws.onopen = function () {
        ws.send(JSON.stringify({fname: 'get_oracle_ip'}));
    }
    ws.onmessage = async function (event) {
        data = JSON.parse(event.data);
        if (data['fname'] == 'return_oracle_ip') {
            ws.close();
	    if (data['ip'].toUpperCase() == "N/A") {
            f.errorHandler("No enclave available, try again in a bit or try a different registry.");
        }
	    console.warn(`Received oracle IP ${data['ip']} from registry. Waiting 11s for it to get ready, then connecting...`);
	    setTimeout(async () => {await connect(data['ip'])}, 11000);
	}
    }

    async function connect(oracleIP) {
	var ws = new WebSocket("wss://" + oracleIP + ":8080/");
	var ETHkey = null;
	var AESkey = null;
	var encryptedAESkey = null;
	var xpraFinished = null;
	ws.onopen = function(event) {ws.send(JSON.stringify({fname: 'get_attestation'}))};
	ws.onmessage = async function (event) {
            data = JSON.parse(event.data);
	    if (data['fname'] == "attestation") {
                [ETHkey, AESkey, encryptedAESkey] = await extractContentIfValid(data['attestation']);
		ws.send(JSON.stringify({fname: 'submit_AES', encrypted_AES: encryptedAESkey}));
		const signThis = ethers.utils.arrayify("0x" + data['signThis']);
		ws.send(JSON.stringify({fname: 'submit_signature',
					signature: await opencontracts.signer.signMessage(signThis)}));
		f.oracleData.fname = 'submit_oracle';
		ws.send(JSON.stringify(await encrypt(AESkey, f.oracleData)));
		ws.send(JSON.stringify(await encrypt(AESkey, {fname: 'run_oracle'})));
	    } else if (data['fname'] == "busy") {
            f.errorHandler("Oracle is busy. Request a new IP.");
	    }
	    if (data['fname'] == 'encrypted') {
	        data = await decrypt(AESkey, data);
		if (data['fname'] == "print") {
		    await f.printHandler(data['string']);
		} else if (data['fname'] == "xpra") {
		    xpraFinished = false;
		    const xpraExit = new Promise((resolve, reject) => {setInterval(()=> {if (xpraFinished) {resolve(true)}}, 1000)});
	            setTimeout(async () => {await f.xpraHandler(data['url'], data['session'], xpraExit)}, 5000);
		} else if (data["fname"] == 'xpra_finished') {
                    console.warn("xpra finished.");		
		    xpraFinished = true;
		} else if (data['fname'] == 'user_input') {
		    userInput = await f.inputHandler(data['message']);
		    ws.send(JSON.stringify(await encrypt(AESkey, {fname: 'user_input', input: userInput})));
		} else if (data['fname'] == 'submit') {
		    await f.submitHandler(async function() {
		        return await requestHubTransaction(opencontracts, data['nonce'], data['calldata'], data['oracleSignature'],
							    data['oracleProvider'], data['registrySignature']);
		    });
		} else if (data['fname'] == 'error') {
		    await f.errorHandler(data['traceback'])
		}
	    }
	}
    }
}

async function ethereumTransaction(opencontracts, f) {
    args = [];
    for (let i = 0; i < f.inputs.length; i++) {args.push(f.inputs[i].value)}
    if (f.stateMutability == 'payable') {
        const msgValue = ethers.utils.parseEther(args.shift());
        args.push({value: msgValue});
    }
    return await opencontracts.contract.connect(opencontracts.signer).functions[f.name].apply(this, args);
}


async function githubOracleDownloader(user, repo, ref, dir) {
    var links = await GITHUB_FILES.content_links_json(user, repo, ref, dir);
    const downloadAsBase64 = async function (link) {
        const url = new URL(link);
        const response = await fetch(url);
        return btoa(new Uint8Array(await response.arrayBuffer()).reduce(
            (data, byte) => {return data + String.fromCharCode(byte);}, '')
        );
    }
    const downloads = Object.entries(links).map(
	     ([file, link]) => [file, downloadAsBase64(link)]
    );
    return Object.fromEntries(downloads);
}


async function getOraclePys(user, repo, ref) {
    const response = await fetch(new URL(`https://raw.githubusercontent.com/${user}/${repo}/${ref}/interface.json`));
    var contract = JSON.parse(await response.text());
    var contract = contract[Object.keys(contract)[0]]
    var oraclePys = {};
    for (let i = 0; i < contract.abi.length; i++) {
        if (contract.abi[i].oracleFolder == undefined) {continue}
        if (oraclePys[contract.abi[i].oracleFolder] == undefined) {
            oraclePys[contract.abi[i].oracleFolder] = {fnames: []};
            const response = await fetch(new URL(
                `https://raw.githubusercontent.com/${user}/${repo}/${ref}/${contract.abi[i].oracleFolder}/oracle.py`
            ));
            oraclePys[contract.abi[i].oracleFolder].file = await response.text();
	}
        oraclePys[contract.abi[i].oracleFolder].fnames.push(contract.abi[i].name);
    }
    return oraclePys;
}


async function OpenContracts() {
    const opencontracts = {};
    // detect metamask
    if (window.ethereum) {
        await init()
    } else {
        window.addEventListener('ethereum#initialized', init, {once: true});
        setTimeout(init, 5000);
    }
    async function init() {
        const {ethereum} = window;
        if (ethereum && ethereum.isMetaMask) {
            window.ethereum.on('chainChanged', (_chainId) => window.location.reload());
            window.ethereum.request({method: 'eth_requestAccounts'});
            opencontracts.provider = new ethers.providers.Web3Provider(ethereum, 'any');
            opencontracts.network = (await opencontracts.provider.getNetwork()).name;
            opencontracts.signer = opencontracts.provider.getSigner();
        } else {
            throw new Error("No Metamask detected.");
        }
    }
    
    // instantiates the contracts
    opencontracts.parseContracts = function (oc_interface, contract_interface) {
        if (!(opencontracts.network in oc_interface)) {
            var errormsg = "Your Metamask is set to " + opencontracts.network + ", which is not supported by Open Contracts.";
            throw new Error(errormsg + " Set your Metamask to one of: " +  Object.keys(oc_interface));
        } else {
            const token = oc_interface[opencontracts.network].token;
            opencontracts.OPNtoken = new ethers.Contract(token.address, token.abi, opencontracts.provider);
            const forwarder = oc_interface[opencontracts.network].forwarder;
            opencontracts.OPNforwarder = new ethers.Contract(forwarder.address, forwarder.abi, opencontracts.provider);
            const hub = oc_interface[opencontracts.network].hub;
            opencontracts.OPNhub = new ethers.Contract(hub.address, hub.abi, opencontracts.provider);
            opencontracts.getOPN = async function (amountString) {
                const amount = ethers.utils.parseEther(amountString);
                await opencontracts.OPNtoken.connect(opencontracts.signer).mint(amount);
	    }
	    opencontracts.approveOPN = async function (amountString) {
		const amount = ethers.utils.parseEther(amountString);
		await opencontracts.OPNtoken.connect(opencontracts.signer).approve(opencontracts.OPNhub.address, amount);
	    }
        }
        
        if (!(opencontracts.network in contract_interface)) {
            var errormsg = "Your Metamask is set to " + opencontracts.network + ", which is not supported by this contract.";
            throw new Error(errormsg + " Set your Metamask to one of: " +  Object.keys(contract_interface));
        } else {
            const contract = contract_interface[opencontracts.network];
            opencontracts.contract = new ethers.Contract(contract.address, contract.abi, opencontracts.provider);
            opencontracts.contractName = contract.name;
            opencontracts.contractDescription = contract.description;
            opencontracts.contractFunctions = [];
            for (let i = 0; i < contract.abi.length; i++) {
                if (contract.abi[i].type == 'constructor') {continue}
                const f = {};
                f.name = contract.abi[i].name;
                f.description = contract.abi[i].description
                f.stateMutability = contract.abi[i].stateMutability;
                f.oracleFolder = contract.abi[i].oracleFolder;
                f.requiresOracle = (f.oracleFolder != undefined);
                if (f.requiresOracle) {
                    f.printHandler = async function(message) {
			    console.warn(`Warning: using default (popup) printHandler for function ${f.name}`); 
			    alert(message);
                    };
                    f.inputHandler = async function (message) {
			    console.warn(`Warning: using default (popup) inputHandler for function ${f.name}`); 
			    return prompt(message);
		    };
                    f.xpraHandler = async function(targetUrl, sessionUrl, xpraExit) {
                        console.warn(`Warning: using default (popup) xpraHandler for function ${f.name}`); 
                        if (window.confirm(`open interactive session to {targetUrl} in new tab?`)) {
                            var newWin = window.open(sessionUrl,'_blank');
                            xpraExit.then(newWin.close);
                            if(!newWin || newWin.closed || typeof newWin.closed=='undefined') {
                                alert("Could not open new window. Set your browser to allow popups and click ok.");
                                f.xpraHandler(targetUrl, sessionUrl);
                            }
                        }
		    };
		    f.errorHandler = async function (message) {
			    console.warn(`Warning: using default (popup) errorHandler for function ${f.name}`); 
			    alert("Error in enclave. Traceback:\n" + message);
		    };
		    f.submitHandler = async function (submit) {
			    console.warn(`Warning: using default (popup) submitHandler for function ${f.name}`); 
			    message = "Oracle execution completed. Starting final transaction. ";
			    alert(message + "It will fail if you did not grant enough $OPN to the hub.");
			    await submit()
		    };
		}
                f.inputs = [];
                if (f.stateMutability == "payable") {
                    f.inputs.push({name: "messageValue", type: "uint256", value: null});
                }
                if (!f.requiresOracle) {
                    for (let j = 0; j < contract.abi[i].inputs.length; j++) {
                        const input = contract.abi[i].inputs[j];
                        f.inputs.push({name: input.name, type: input.type, value: null});
                    }
                }
                f.call = async function (state) { // option to provide inputs is useful for frameworks like React where state may have been cloned
                    _f = state || f
                    const unspecifiedInputs = _f.inputs.filter(i=>i.value == null).map(i => i.name);
                    if (unspecifiedInputs.length > 0) {
                        throw new Error(`The following inputs to "${_f.name}" were unspecified:  ${unspecifiedInputs}`);
                    }
                    for (let i = 0; i < _f.inputs.length; i++) {
                        if ((_f.inputs[i].type === "bool") && (typeof _f.inputs[i].value === 'string')) {
                            _f.inputs[i].value = JSON.parse(_f.inputs[i].value.toLowerCase());
                        }
                    }
                    if (_f.requiresOracle) {
                        if (_f.oracleData == undefined) {
                            throw new Error(`No oracleData specified for "${_f.name}".`)
                        } else {
                            console.log("oracle data: ", _f.oracleData);
                            files = Object.keys(_f.oracleData);
                            if (!files.includes("oracle.py")) {throw new Error("No oracle.py in f.oracleData!")}
                            if (!files.includes("requirements.txt")) {throw new Error("No requirements.txt in oracleData!")}
                            if (!files.includes("domain_whitelist.txt")) {throw new Error("No domain_whitelist.txt in f.oracleData!")}
                            for (let i = 0; i < files.length; i++) {
                                f.oracleData[files[i]] = await f.oracleData[files[i]];
                            }
                            return await enclaveSession(opencontracts, _f);
                        }
                    } else {
                        return await ethereumTransaction(opencontracts, _f);
                    }
                }
                opencontracts.contractFunctions.push(f);
            }
        }
    }
    
    return opencontracts;
}



