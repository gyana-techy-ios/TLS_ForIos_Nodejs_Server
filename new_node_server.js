const tls = require('tls');
const fs = require('fs');
var crypto = require("crypto");

// console.log("Supported curves are " + crypto.getCurves());
const bob = crypto.createECDH('secp128r1');

let certData = fs.readFileSync('certificate/b9/b9.crt.der');
let serverPrivateKey = fs.readFileSync('certificate/b9/b9_private.key');
let serverPublicKey = fs.readFileSync('certificate/b9/b9_public.key');

var iv = Buffer.from('1234567812345678');
var CIPHER_ALGORITHM = 'aes-256-cbc';

var myPublicKey = new Buffer('');
var mySharedSecretKey;
var myHashKey;

const options = {
    key: fs.readFileSync('certificate/b9/b9_private.key'),
    cert: fs.readFileSync('certificate/b9/b9_cert.crt'),
    rejectUnauthorized: true
};

const client_random = "Hello"; // _client
const server_random = "Hello"; // _server
const server = tls.createServer(options, (socket) => {
    var remoteAddress = socket.remoteAddress + ':' + socket.remotePort;
    console.info(`\n************{ Step 0 Start }*************\n : -> Client connected with Robot = Remote IP: ${socket.remoteAddress} Port: ${socket.remotePort}\n************{ Step 0 End}*************\n`);
    socket.setEncoding('utf8');
    socket.on('data', function (req) {
        if (req.toString().trim() == "Hello") {
            console.log("\n************{ Step 1 Start }*************\n : -> Client says = " + req + "\n************{ Step 0 End}*************\n");

            let b9CftSent = socket.write(certData, (error) => {
                if (error == null) {
                    console.log("\n************{ Step 2 Start }*************\n : -> Robot replies with B9 certificate = " + certData.length + "\n************{ Step 2 End}*************\n");
                } else {
                    console.log('Eror while sending data ' + error);
                }
            });
            if (b9CftSent == true) {

                /*
                /// ECDH key generation part 
                /// ECDH key will generate from server side using :- crypto.createECDH('secp128r1')
                */
                let myPrivateKey = bob.generateKeys('base64', 'compressed').publicKey;
                myPublicKey = bob.getPublicKey(); // ECDH public key

                let signatureDigest = Buffer.concat([myPublicKey, new Buffer(client_random), new Buffer(server_random)]);
                const digestEcdhPubKey = crypto.createHash('sha256').update(signatureDigest).digest();
                console.log("Final signature digest ->> " + digestEcdhPubKey.toString('base64'));
                console.log("Robot public key (Base 64) -- " + myPublicKey.toString('base64') + "\n Public key length = " + myPublicKey.length);

                const sign = crypto.createSign('sha256', {
                    padding: crypto.constants.RSA_PKCS1_PADDING,
                    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
                });
                sign.write(digestEcdhPubKey);
                sign.end();
                const newsignature = sign.sign(serverPrivateKey, 'base64');

                const verify = crypto.createVerify('sha256', {
                    padding: crypto.constants.RSA_PKCS1_PADDING,
                    saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
                });
                verify.write(digestEcdhPubKey);
                verify.end();
                let signVerify = verify.verify(serverPublicKey, newsignature, 'base64');
                console.log("New Method Signature Verification : " + signVerify + "\n\n\n\n\n\n\n\n");

                var publicKey = new Buffer(myPublicKey)
                var signatureBuf = Buffer.from(newsignature)

                console.log("publicKey : " + publicKey);
                console.log("\nSignature : " + signatureBuf + "Signature Length : " + signatureBuf.length);

                var cerpubkeysign = new Buffer.concat([publicKey, signatureBuf]);

                console.log("Final Payload of step-2 (ECDH public key + Signature): Length >>> " + cerpubkeysign.length);
                let b9CftSent = socket.write(Buffer.from(cerpubkeysign), (error) => {
                    if (error == null) {
                        console.log("\n************{ Step 3 Start }*************\n : -> Robot replies with PublicKey Signature = " + cerpubkeysign.length + "\n************{ Step 3 End}*************\n");
                    } else {
                        console.log('Eror while sending data ' + error);
                    }
                });
            }
            // socket.pipe(socket);
            socket.setEncoding('hex');
        } else if (req.length > 1024) {

            console.log("\n************{ Step 5 Start }*************\n : -> Client sent his certificate with shared secret key (session key)  signature = " + req + "\n************{ Step 5 End}*************\n");

            let clientReq = Buffer.from(req, 'hex');

            let clientCertificate = clientReq.slice(0, 1326)
            console.log("Client certificate : " + clientCertificate + "\nLength : " + clientCertificate.length + "\n");

            let clientsharedKey = clientReq.slice(clientCertificate.length, clientCertificate.length + 33)

            console.log("client SessionKey : " + clientsharedKey + "Length : " + clientsharedKey.length);

            var sharedScret = bob.computeSecret(clientsharedKey);
            mySharedSecretKey = sharedScret

            var clientSignature = clientReq.slice(clientsharedKey.length + clientCertificate.length, clientReq.length);

            console.log("\n\nClient Digital signature : " + clientSignature + " signature Length : " + clientSignature.length);

            let signatureDigest = Buffer.concat([myPublicKey, new Buffer(client_random), new Buffer(server_random)]);

            const verify = crypto.createVerify('sha256', {
                padding: crypto.constants.RSA_PKCS1_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
            });
            verify.write(signatureDigest);

            console.log("\n\nClient Digital signature : " + clientSignature.toString('base64'));

            let signVerify = verify.verify(serverPublicKey, clientSignature.toString('base64'));
            verify.end();

            console.log("\n\nClient Digital signature verification result : " + signVerify);

            if (signVerify == false) {
                console.log("\n\nRobot shared secret = " + mySharedSecretKey.toString('base64') + "  length - " + Buffer.from(mySharedSecretKey).length);

                let hash = crypto.createHash('sha256').update(mySharedSecretKey).digest();
                myHashKey = hash
                console.log("\n\nRobot Hash is 1 ->" + hash.toString('base64'));

                var cipher = crypto.createCipheriv(CIPHER_ALGORITHM, hash, iv);
                var ciphertext = cipher.update(new Buffer("Completed"));
                var encrypted = Buffer.concat([iv, ciphertext, cipher.final()]);

                console.log("\n\nRobot encrtyped Completed message is : ->> " + encrypted);
                console.log("\n\nRobot encrtyped Completed message is in Base64 : ->> " + encrypted.toString('base64'));
                console.log("\n\nRobot encrtyped Completed message is Uint8Array ->> " + Uint8Array.from(encrypted));
                
                socket.write(encrypted, (error) => {
                    if (error == null) {
                        console.log("\n************{ Step 6 Start }*************\n : -> Robot sent Completed message with Encryption" + "\n************{ Step 6 End}*************\n");
                    } else {
                        console.log('Eror while sending data ' + error);
                    }
                });
            }

        } else {

            console.log("\n************{ Step 7 Start }*************\n : -> Client sent Completed message with Encryption = " + req + "\n************{ Step 7 End}*************\n");
            let encryptedReq = Buffer.from(req, 'hex');
            // console.log("\n\nPrint Client Req typcase to buffer = " + encryptedReq + "\n");
            // console.log("\n\nPrint Client Req typcase to Uint8Array = " + (new Uint8Array(encryptedReq)) + "\n");
            let decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, myHashKey, iv);
            let plaintext = decipher.update(encryptedReq) + decipher.final();
            console.log("\n************{ Step 8 Start }*************\n : -> Robot read Completed message with Decryption = " + plaintext.toString('base64') + "\n************{ Step 8 End}*************\n");
            if (plaintext == "Completed") {
                var finishcipher = crypto.createCipheriv(CIPHER_ALGORITHM, myHashKey, iv);
                var ciphertext = finishcipher.update(new Buffer("Finished"));
                let encrypted = Buffer.concat([iv, ciphertext, finishcipher.final()]);

                // ///******** */
                // var localdecipher = crypto.createDecipheriv(CIPHER_ALGORITHM, myHashKey, iv);
                // var decrypttext = encrypted.slice(16);
                // var localplaintext = localdecipher.update(decrypttext) + localdecipher.final();
                // console.log("(1) ***** My decrtyped message is -> -> " + localplaintext.toString('base64'));
                // ////************* */

                console.log("1 -> Finished encrypted : " + encrypted);
                console.log("1 -> Finished in base64 : ->> " + encrypted.toString('base64'));
                console.log("2 -> Finished encrypted Length : " + encrypted.length);
                console.log("\n\nFinished encrtyped message is Uint8Array ->> " + Uint8Array.from(encrypted));

                // executes after one second, and blocks the thread
                socket.write(encrypted, (error) => {
                    if (error == null) {
                        console.log("\n************{ Step 9 Start }*************\n : -> Robot sent Finished message with encryption \n************{ Step 9 End}*************\n");
                    } else {
                        console.log('Eror while sending data ' + error);
                    }
                });
            } else if (plaintext == "Finished") {
                console.log("\n************{ Step 9 Start }*************\n : -> TLS Finished \n************{ Step 9 End}*************\n");
            } else {
                console.log("Command request");
                value = JSON.parse(plaintext);
                console.log("Read request command = " + value); 
                console.log("Read request command name = " + value["cmd"]); 
                if (value["cmd"] == "TestCode") {
                    var resdict = {
                        "type" : 'response',
                        "cmd" :  value.cmd,
                        'result' :  '200',
                        'data' : "Authenticated Robot."
                      };
                      var msgs2 = JSON.stringify(resdict);
                    var finishciphercmd = crypto.createCipheriv(CIPHER_ALGORITHM, myHashKey, iv);
                    var ciphertextcmd = finishciphercmd.update(new Buffer(msgs2));
                    let encryptedcmd = Buffer.concat([iv, ciphertextcmd, finishciphercmd.final()]);

                      socket.write(encryptedcmd);
                    
                }
            }
        }
    });

    socket.on('error', (error) => {
        console.log(error);
    });

    socket.on('close', function () {
        myHashKey = null;
        myPublicKey = new Buffer('');
        console.log('connection from %s closed', remoteAddress);
    });

});

server.on("connection", (socket) => {
    var remoteAddress = socket.remoteAddress + ':' + socket.remotePort;
    console.log('Client connected from ' + remoteAddress);
    socket.setKeepAlive(true, 60000); //1 min = 60000 milliseconds.
    // initialize this client's sequence number
    // sequenceNumberByClient.set(socket, 1);
    // sock.write(msgs2);
    // when socket disconnects, remove it from the list:
    socket.on("disconnect", () => {
        sequenceNumberByClient.delete(socket);
        console.info(`Client gone [id=${socket.id}]`);
    });

});

var HOST = '127.0.0.1'; // "192.168.0.104"

server.listen(8800, HOST, () => {
    console.log('server listening on %j', server.address());
});




// Not required
// var myPrivateKey = new Buffer('');
//         myPrivateKey = new Buffer('');

                // myPrivateKey = bob.getPrivateKey();
            // console.log("\n\nNode Debug Log: Robot privatekey Raw data 1 ----- " + myPrivateKey);
            // console.log("\n\nNode Debug Log: Robot privatekey (Base 64) 2 -----" + myPrivateKey.toString('base64'));
                             // myPrivateKey = bob.generateKeys('base64', 'compressed').publicKey;
