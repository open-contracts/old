// credit to themighty1 @ TLSNotary
// this file is not used by the website, it serves as an input to to create cose.js with:
// browserify cose_source.js --standalone COSE > cose.js

const cose = require('cose-js');

// x, y, doc is an ArrayBuffer
const verify = function (x, y, doc) {

    const verifier = {'key': {'x': Buffer.from(x), 'y': Buffer.from(y)}};

    cose.sign.verify(Buffer.from(doc), verifier, {defaultType: 18})
            .then((buf) => {
            console.log("Verification successful")
            }).catch((error) => {console.log(error);});
}

if (typeof module !== 'undefined'){ //we are in node.js environment
    module.exports={
        verify
    }
}
