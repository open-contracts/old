var opencontracts = null;

async function loadOpenContract() {
    opencontracts = await OpenContracts(window);
    
    // need to get the JSONs
    const link = "https://raw.githubusercontent.com/" + $('#contractGithub').val();
    const contract_interface = JSON.parse(await (await fetch(new URL(link + "/interface.json"))).text());
    const oc_interface = JSON.parse(await (await fetch('client-protocol/opencontracts_interface.json')).text());
    
    // now go throught he functions.
    opencontracts.parseContracts(oc_interface, contract_interface);
    fnButtons = "<p><b>Contract Functions:</b></p>";
    for (let i = 0; i < opencontracts.contractFunctions.length; i++) {
        const f = opencontracts.contractFunctions[i];
        // 
        //  Create a button for every function f, which has the following properties:
        //      f.name = "someString"
        //      f.description = "someString"
        //      f.requiresOracle in {true, false} 
        //      f.stateMutability in {"view", "pure", "nonpayable", "payable"}
        //      f.inputs = list[input], where:
        //                      input.name = "someString"
        //                      input.type = "someSolidityVariableType" (e.g. "uint256")
        //                      input.value = null      (needs to be set by you before calling f.call() )
        //      f.call() (exectues the function)
        //
        //  Need to specify:
        //       input.value for every input
        //       if f.requiresOracle: 
        //          f.oracleData = {filename1: b64encoded, filename2: b64encoded, ...}  representing the f.oracleFolder from the repo. Use "githubOracleDownloader" like below.      
        window['show' + f.name] = function () {showFunction(f)};
        fnButtons += `<input id=${f.name} type="submit" value="${f.name}" onclick="${'window.show' + f.name}()" />`;
    }
    $('#functionNames').html(fnButtons);
    $('#currentFunction').html("");
    $('#results').html("");
}


async function showFunction(f) {
    var currentFunction = `<p><b>Function name:</b>  ${f.name}</p>`;
    currentFunction += `<p><b>State mutability:</b> ${f.stateMutability}</p>`;
    currentFunction += '<form id="contractForm" action="javascript:void(0);"> <p><b>Arguments:</b>';
    for (let i = 0; i < f.inputs.length; i++) {
        currentFunction += `<div><label for="${f.inputs[i].name}"> ${f.inputs[i].name} (${f.inputs[i].description}):</label> <input id="${f.inputs[i].name}" type="text" value="" size="60" /></div>`;
    }
    if (f.requiresOracle) {
        // Optionally specify:
        //      f.printHandler = async function (message) {};
        //      f.inputHander = async function (message) {return userInput};
        //      f.xpraHandler = async function (targetUrl, sessionUrl, xpraExit) {win = open(sessionUrl); xpraExit.then(win.close())};
        //      f.errorHandler = async function (message) {}
        //      f.submitHandler = async function (metamaskTx) {await metamaskTx(); };
        //
        const [user, repo, ref] =  $('#contractGithub').val().split("/");
        window["oracleLoader"] = async function () {
            f.oracleData = await githubOracleDownloader(user, repo, ref, f.oracleFolder);
            files = Object.keys(f.oracleData);
            for (let i = 0; i < files.length; i++) {
                f.oracleData[files[i]] = await f.oracleData[files[i]];
            }
            console.log(f.oracleData, f.oracleFolder);
            document.getElementById('callButton').disabled = false;
            document.getElementById('loadOracle').disabled = true;
        };
        currentFunction += `<div><label for="loadOracle">Load Oracle Data (this may take a bit): </label><input id="loadOracle" type="submit" value="Load" onclick="window.oracleLoader()" /></div>`;  
    }
    
    // create a "call" button
    currentFunction +=`<br> <br> <input id="callButton" type="submit" value="Call" onclick="${'window.call' + f.name}()"/> </form>`;
    window['call' + f.name] = async function () {
        // sets the input.value for every input
        for (let i = 0; i < f.inputs.length; i++) {f.inputs[i].value = $(`#${f.inputs[i].name}`).val()}
        // calls the function
        const url = new URL(window.location.href);
        const registryOverride = url.searchParams.get('registryIP');
        console.log("override:", registryOverride);
        if (registryOverride != null) {f.registryIP = registryOverride}
        $('#results').html(await f.call());
    };
    $('#currentFunction').html(currentFunction);
    document.getElementById('callButton').disabled = f.requiresOracle;
    $('#results').html("");
}
