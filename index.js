async function loadOpenContract() {
    var interface = await OpenContracts(window);
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

async function showFunction(f) {
    var currentFunction = `<p><b>Function name:</b>  ${fname}</p>`;
    currentFunction += `<p><b>State mutability:</b> ${fjson.stateMutability}</p>`;
    currentFunction += '<form id="contractForm" action="javascript:void(0);"> <p><b>Arguments:</b>';
    for (let i = 0; i < f.inputs.length; i++) {
        currentFunction += `<div>	<label for="${f.inputs[i].name}"> ${f.inputs[i].name} (${f.inputs[i].description}):	</label> <input id="${f.inputs[i].name}" type="text" value="" size="60" /></div>`;
    }
    $('#currentFunction').html(currentFunction);
}
