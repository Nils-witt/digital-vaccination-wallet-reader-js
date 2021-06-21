import {DVWR} from "./DVWR";


(async () => {
    let decoder = new DVWR();
    let decoded: any = await decoder.readQrCode("HC1:...");

    console.log(decoder.readCertificate(decoded.content));
})()

