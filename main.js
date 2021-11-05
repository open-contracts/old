


async function enclaveSession(interface, f) {

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



async function OpenContracts(window) {
    const interface = {};
    
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
                f.inputs = [];
                if (f.stateMutability == "payable") {
                    f.inputs.push({name: "messageValue", type: "uint256", value: null,
                                   description: "The value (in ETH) of the transaction."});
                }
                if (f.oracleFolder != undefined) {
                    f.inputs.push({name: "oracleFolder", type: "object", value: null,
                                   description: "The oracle folder, encoded as {filename1: byte64encoded, ...} object."});
                    f.inputs.push({name: "ioHandler", type: "function", value: null,
                                   description: "Handles enclave interaction, receiving and returning JSONs."});
                } else {
                    for (let j = 0; j < contract.abi[i].inputs.length; j++) {
                        const input = contract.abi[i].inputs[j];
                        f.inputs.push({name: input.name, type: input.type, description: input.description, value: null});
                    }
                }
                f.call = async function () {
                    if (f.oracleFolder != undefined) {
                        return await enclaveSession(interface, f);
                    } else {
                        return await ethereumTransaction(interface, f);
                    }
                }
                f.return = null;
                interface.contractFunctions.push(f);
            }
        }
    }
    
    return interface;
}
