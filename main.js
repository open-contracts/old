
//++ import { oc } from "opencontracts";
// A Web3Provider wraps a standard Web3 provider, which is
// what Metamask injects as window.ethereum into each page
const provider = new ethers.providers.Web3Provider(window.ethereum)


//// TODO: const openProvider = new oc.providers.Web3Provider(provider)
     //// handling the logic of ec2 and enclave communication

// The Metamask plugin also allows signing transactions to
// send ether and pay to change state within the blockchain.
// For this, you need the account signer...
const user = provider.getSigner()

// makes contract a global variable
var contract = null;

// executed by "Load Contract" button
function loadContract() {
  // Load Contract
	var contractAddress = $('#contractAddress').val();
  var contractABI = JSON.parse($('#contractABI').val());
  contract = new ethers.Contract(contractAddress, contractABI, provider).connect(user);
  var contractFunctions = contract.interface.fragments;
    
  // add a button for every function in our contract
  var fnames = "<p><b>Functions:</b></p>";
  for (let i = 1; i < contractFunctions.length; i++) {
    fname = contractFunctions[i].name;
    fnames += `<input id=${fname} type="submit" value="${fname}" onclick="showFunction(${fname})" />`;
	}
  fnames += "<br />"
  $('#functionNames').html(fnames);
  $('#currentFunction').html("");
  $('#results').html("");
}

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
