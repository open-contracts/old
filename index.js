var interface = null;

async function loadOpenContract() {
    interface = await OpenContracts(window);
    const link = "https://raw.githubusercontent.com/" + $('#contractGithub').val();
    const contract_interface = JSON.parse(await (await fetch(new URL(link + "/interface.json"))).text());
    const oc_interface = JSON.parse(await (await fetch('opencontracts_interface.json')).text());
    interface.parseContracts(oc_interface, contract_interface);
    fnButtons = "<p><b>Contract Functions:</b></p>";
    for (let i = 0; i < interface.contractFunctions.length; i++) {
        fname = interface.contractFunctions[i].name;
        window['show' + fname] = function () {showFunction(interface.contractFunctions[i])};
        fnButtons += `<input id=${fname} type="submit" value="${fname}" onclick="${'window.show'+fname}()" />`;
    }
    $('#functionNames').html(fnButtons);
    $('#currentFunction').html("");
    $('#results').html("");
}

async function printHandler() {0}
async function inputHandler() {0}
async function xpraHandler() {0}
async function errorHandler() {0}

async function showFunction(f) {
    var currentFunction = `<p><b>Function name:</b>  ${f.name}</p>`;
    currentFunction += `<p><b>State mutability:</b> ${f.stateMutability}</p>`;
    currentFunction += '<form id="contractForm" action="javascript:void(0);"> <p><b>Arguments:</b>';
    for (let i = 0; i < f.inputs.length; i++) {
        currentFunction += `<div><label for="${f.inputs[i].name}"> ${f.inputs[i].name} (${f.inputs[i].description}):</label> <input id="${f.inputs[i].name}" type="text" value="" size="60" /></div>`;
    }
    if (f.requiresOracle) {
        document.getElementById('callButton').disabled = true;
        f.printHandler = printHandler;
        f.inputHander = inputHandler;
        f.xpraHandler = xpraHandler;
        f.errorHandler = errorHandler;
        const [user, repo, ref] =  $('#contractGithub').val().split("/");
        window["oracleLoader"] = async function () {
            f.oracleData = await githubOracleDownloader(user, repo, ref, f.oracleFolder)
            document.getElementById('callButton').disabled = false;
        };
        currentFunction += `<div><label for="loadOracle">Load Oracle Data (this may take a bit): </label><input id="loadOracle" type="submit" value="Load" onclick="window.oracleLoader()" /></div>`;  
    }
    window['call' + f.name] = async function () {
        for (let i = 0; i < f.inputs.length; i++) {f.inputs[i].value = $(`#${f.inputs[i].name}`).val()}
        $('#results').html(await f.call());
    };
    currentFunction +=`<br> <br> <input id="callButton" type="submit" value="Call" onclick="${'window.call' + f.name}()" disabled="${f.requiresOracle}"/> </form>`;
    $('#currentFunction').html(currentFunction);
    $('#results').html("");
}
