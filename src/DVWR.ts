// @ts-ignore
import * as cose from "cose-js"
import {createHash} from 'sha256-uint8array'
import {inflate} from 'pako'
import {decode} from 'cbor'
import {Buffer} from 'buffer'

import {getCerts} from './certificates'
// @ts-ignore
import * as base45 from "base45";


export class DVWR {
    verifiers: any;
    certs: any;

    constructor() {
        this.certs = getCerts();
        this.verifiers = this.getCertificateVerifiers(this.certs);
    }

    getCertificateVerifiers(certs: any) {
        return certs.map((v: any) => {
            const fingerprint = createHash().update(v.raw).digest()
            const id = fingerprint.slice(0, 8)

            const pk = v.publicKey.keyRaw
            const keyX = Buffer.from(pk.slice(1, 1 + 32))
            const keyY = Buffer.from(pk.slice(33, 33 + 32))

            return {
                key: {
                    'x': keyX,
                    'y': keyY,
                    'kid': id,
                },
                about: {
                    issuer: v.issuer.organizationName,
                    country: v.issuer.countryName,
                },
            }
        })
    }

    decodePayload(inData: any) {
        let outData = inData.substring(4);
        outData = base45.decode(outData);
        if (outData[0] === 0x78) {
            outData = inflate(outData);
        }
        return outData;
    }

    readQrCode(payload: any) {
        return new Promise(async (resolve, reject) => {

            const data = this.decodePayload(payload)
            const verifyResult = await Promise.all(this.verifiers.map(async (verifier: any) => {
                try {
                    const buf = await cose.sign.verify(data, verifier)
                    return {
                        content: decode(buf),
                        issuer: verifier.about.issuer,
                        country: verifier.about.country,
                    }
                } catch (e) {
                    return null
                }
            }));

            const cert = verifyResult.find(v => v !== null)
            if (cert === undefined) {
                reject('No Cert')
                return
            }
            resolve(cert);
        });
    }

    readCertificate(payload: any) {
        const sensitive = payload.get(-260).get(1)
        let out: { certificates: any[], person: any } = {
            certificates: [],
            person: {}
        }

        out.person = {
            Birthday: sensitive.dob,
            Surname: sensitive.nam.fn,
            SurnameStandardised: sensitive.nam.fnt,
            Forename: sensitive.nam.gn,
            ForenameStandardised: sensitive.nam.gnt,
        }

        payload.get(-260).get(1).v.forEach((cert: any) => {
            out.certificates.push({
                CertificateIdentifier: cert.ci,
                CountryOfVaccination: cert.co,
                DoseNumber: cert.dn,
                DateOfVaccination: cert.dt,
                CertificateIssuer: cert.is,
                MarketingAuthorizationHolder: cert.ma,
                VaccineMedicinalProduct: cert.mp,
                TotalSeriesOfDoses: cert.sd,
            })
        });
        return out
    }


}