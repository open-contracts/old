function hexStringToArray(hexString) {
    var pairs = hexString.match(/[\dA-F]{2}/gi);
    var integers = pairs.map(function(s) {return parseInt(s, 16);});
    return new Uint8Array(integers);
}


async function getOracleIP() {
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

async function enclaveSession(interface, f) {
    const registryIP = hexStringToArray(await interface.OPNhub.registryIpList(0)).join(".");
    var ws = new WebSocket("wss://" + registryIP + ":8080/");
    ws.onopen = function () {
        ws.send(JSON.stringify({fname: 'get_oracle_ip'}));
    }
    var oracleIP = new Promise();
    ws.onmessage = async function (event) {
        data = JSON.parse(event.data);
        if (data['fname'] == 'return_oracle_ip') {
            oracleIP.resolve(data['ip']);
            ws.close();
	}
    }
    var oracleIP = await oracleIP;
    if (oracleIP  == "N/A") {throw "Curently no oracle enclave available. Try again in a bit."} 
    console.log(oracleIP);
}

async function ethereumTransaction(interface, f) {
    args = [];
    for (let i = 0; i < f.inputs.length; i++) {args.push(f.inputs[i].value)}
    if (f.stateMutability == 'payable') {
        const msgValue = ethers.utils.parseEther(args.shift());
        args.push({value: msgValue});
    }
    return await interface.contract.connect(interface.signer).functions[f.name].apply(this, args);
}


async function githubOracleDownloader(user, repo, ref, dir) {
    var links = await GITHUB_FILES.content_links_json(user, repo, ref, dir);
    const downloadAsBase64 = async function (link) {
        const url = new URL(link);
        const response = await fetch(url);
        return btoa(new Uint8Array(await response.arrayBuffer()).reduce((data, byte)=> {return data + String.fromCharCode(byte);}, ''));
    }
    const downloads = Promise.all(Object.entries(links).map(async ([file, link]) => [file, await downloadAsBase64(link)]));
    return Object.fromEntries(await downloads);
}


async function OpenContracts(window) {
    const interface = {};
    interface.window = window;
    // detect metamask
    if (interface.window.ethereum) {
        await init()
    } else {
        interface.window.addEventListener('ethereum#initialized', init, {once: true});
        setTimeout(init, 5000);
    }
    async function init() {
        const {ethereum} = interface.window;
        if (ethereum && ethereum.isMetaMask) {
            interface.window.ethereum.on('chainChanged', (_chainId) => interface.window.location.reload());
            interface.window.ethereum.request({method: 'eth_requestAccounts'});
            interface.provider = new ethers.providers.Web3Provider(ethereum, 'any');
            interface.network = (await interface.provider.getNetwork()).name;
            interface.signer = interface.provider.getSigner();
        } else {
            throw "No Metamask detected.";
        }
    }
    
    // instantiates the contracts
    interface.parseContracts = function (oc_interface, contract_interface) {
        if (!(interface.network in oc_interface)) {
            var errormsg = "Your Metamask is set to " + interface.network + ", which is not supported by Open Contracts.";
            throw errormsg + " Set your Metamask to one of: " +  Object.keys(oc_interface);
        } else {
            const token = oc_interface[interface.network].token;
            interface.OPNtoken = new ethers.Contract(token.address, token.abi, interface.provider);
            const forwarder = oc_interface[interface.network].forwarder;
            interface.OPNforwarder = new ethers.Contract(forwarder.address, forwarder.abi, interface.provider);
            const hub = oc_interface[interface.network].hub;
            interface.OPNhub = new ethers.Contract(hub.address, hub.abi, interface.provider);    
        }
        
        if (!(interface.network in contract_interface)) {
            var errormsg = "Your Metamask is set to " + interface.network + ", which is not supported by this contract.";
            throw errormsg + " Set your Metamask to one of: " +  Object.keys(contract_interface);
        } else {
            const contract = contract_interface[interface.network];
            interface.contract = new ethers.Contract(contract.address, contract.abi, interface.provider);
            interface.contractFunctions = [];
            for (let i = 0; i < contract.abi.length; i++) {
                if (contract.abi[i].type == 'constructor') {continue}
                const f = {};
                f.name = contract.abi[i].name;
                f.stateMutability = contract.abi[i].stateMutability;
                f.oracleFolder = contract.abi[i].oracleFolder;
                f.requiresOracle = (f.oracleFolder != undefined);
                f.inputs = [];
                if (f.stateMutability == "payable") {
                    f.inputs.push({name: "messageValue", type: "uint256", value: null,
                                   description: "The value (in ETH) of the transaction."});
                }
                if (!f.requiresOracle) {
                    for (let j = 0; j < contract.abi[i].inputs.length; j++) {
                        const input = contract.abi[i].inputs[j];
                        f.inputs.push({name: input.name, type: input.type, description: input.description, value: null});
                    }
                }
                f.call = async function () {
                    if (f.requiresOracle) {
                        return await enclaveSession(interface, f);
                    } else {
                        return await ethereumTransaction(interface, f);
                    }
                }
                interface.contractFunctions.push(f);
            }
        }
    }
    
    return interface;
}




