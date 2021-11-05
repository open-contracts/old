async function loadOpenContract() {
    var interface = await OpenContracts(window);
    const link = "https://raw.githubusercontent.com/" + $('#contractGithub').val();
    const contract_interface = JSON.parse(await (await fetch(new URL(link + "/interface.json"))).text());
    const oc_interface = JSON.parse(await (await fetch('opencontracts_interface.json')).text());
    interface.parseContracts(oc_interface, contract_interface);
    fnButtons = "<p><b>Contract Functions:</b></p>";
    for (let i = 0; i < interface.contractFunctions.length; i++) {
        fname = interface.contractFunctions[i].name;
        fnButtons += `<input id=${fname} type="submit" value="${fname}" onclick="showFunction(interface.contractFunctions[i])" />`;
    }
   $('#functionNames').html(fnames);
   $('#currentFunction').html("");
   $('#results').html("");
}
